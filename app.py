#!/usr/bin/python

import sys
from time import sleep
import argparse
import boto3
from bcolors import bcolors
import uuid
import pickle
from botocore.exceptions import ClientError

tenancy = 'default'
dry_run = False
launch_only = False
region = 'us-east-1'
target_ami = 'ami-0dbbd6f952e12feba'

ec2_client = boto3.client('ec2', region_name=region)
dynamodb = boto3.resource('dynamodb', region_name=region)

def recreate_instances(source_instance_ids=[]):
    instances = get_instance(source_instance_ids)

    for instance in instances:
        instance_id = instance['InstanceId']

        if get_instance_details(instance_id) is None:
            save_instance_details(instance)

        recreate_instance(instance_id)

def recreate_instance(instance_id):
    global dry_run
    global launch_only
    global region
    
    instance = get_instance_details(instance_id)
    storage = get_instance_details(instance_id, 'instanceVolumes')

    source_instance_id = instance['InstanceId']

    # Stop source instance
    if get_instance_state(source_instance_id) == 'running':
        stop_instance(source_instance_id)

    # Detach source instance volumes
    print(bcolors.WARNING + "Detaching volumes from source instance: %s" % source_instance_id)
    if get_instance_state(source_instance_id) != 'terminated':
        detach_volumes(source_instance_id, get_instance_details(instance_id, 'instanceVolumes'))
    print(bcolors.OKGREEN + "Detached volumes from source instance: %s" % source_instance_id)

    # Terminate instance
    if get_instance_state(source_instance_id) == 'stopped':
        terminate_instance(source_instance_id)

    # Hydrate data into new instance
    eth0 = instance['NetworkInterfaces'][0]
    
    security_group_ids = []
    for security_group in instance["SecurityGroups"]:
        security_group_ids.append(security_group["GroupId"])

    network_interfaces = []
    for network_interface in instance["NetworkInterfaces"]:
        new_eni = {}
        if "Association" in network_interface and "PublicIp" in network_interface['Association']:
            new_eni['AssociatePublicIpAddress'] = True
        else:
            new_eni['AssociatePublicIpAddress'] = False

        new_eni['DeleteOnTermination'] = network_interface['Attachment']['DeleteOnTermination']
        new_eni['Description'] = network_interface['Description']
        new_eni['DeviceIndex'] = network_interface['Attachment']['DeviceIndex']
        new_eni['Groups'] = []
        new_eni['PrivateIpAddress'] = network_interface['PrivateIpAddress']
        for group in network_interface['Groups']:
            new_eni['Groups'].append(group['GroupId'])
        if len(network_interface['Ipv6Addresses']) > 0:
            new_eni['Ipv6AddressCount'] = len(network_interface['Ipv6Addresses'])
            new_eni['Ipv6Addresses'] = network_interface['Ipv6Addresses']
        
        new_eni['SubnetId'] = network_interface['SubnetId']
        new_eni['InterfaceType'] = network_interface['InterfaceType']

    ### Launch new instance
    print(bcolors.OKGREEN + "Now launching new instance...")
   
    run_instances_response = ec2_client.run_instances(
        ImageId=target_ami,
        InstanceType=instance['InstanceType'],
        PrivateIpAddress=eth0['PrivateIpAddress'],
        Ipv6AddressCount=len(eth0['Ipv6Addresses']),
        Ipv6Addresses=eth0['Ipv6Addresses'],
        KeyName=instance['KeyName'],
        Tenancy=tenancy,
        MaxCount=1,
        MinCount=1,
        Monitoring={
            'Enabled': True if instance['Monitoring']['State'] is not "disabled" else False
        },
        Placement=instance['Placement'],
        SecurityGroupIds=security_group_ids,
        SubnetId=instance['SubnetId'],
        UserData='' if 'UserData' not in instance else instance['UserData'],
        DryRun=dry_run,
        EbsOptimized=instance['EbsOptimized'],
        IamInstanceProfile= {} if 'IamInstanceProfile' not in instance else {
            'Arn': instance['IamInstanceProfile']['Arn']
        },
        NetworkInterfaces=network_interfaces,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': instance['Tags']
            },
        ],
        CapacityReservationSpecification=instance['CapacityReservationSpecification'],
        HibernationOptions={
            'Configured': instance['HibernationOptions']['Configured']
        }
    )

    new_instance_id = run_instances_response['Instances'][0]['InstanceId']

    print(bcolors.OKGREEN + "New instance launched: %s" % new_instance_id)
    print(bcolors.WARNING + "Waiting for new instance ready: %s" % new_instance_id)

    wait_instance_ready(new_instance_id, 'running')

    new_instance = get_instance([new_instance_id])
    new_volumes = build_block_config(new_instance[0])

     # Stop new instance
    stop_instance(new_instance_id)
    
    wait_instance_ready(new_instance_id, 'stopped')

    # Detach volumes from new instance
    print(bcolors.WARNING + "Detaching volumes from new instance: %s" % new_instance_id)
    detach_volumes(new_instance_id, new_volumes)
    print(bcolors.OKGREEN + "Detached volumes from new instance: %s" % new_instance_id)

    ### Attach volumes from source instance to new instance    
    print(bcolors.WARNING + "Attaching volumes to new instance: %s" % new_instance_id)
    attach_volumes(new_instance_id, get_instance_details(instance_id, 'instanceVolumes'))
    print(bcolors.OKGREEN + "Attached volumes to new instance: %s" % new_instance_id)

    ### Delete newly created volumes
    print(bcolors.WARNING + "Delete newly created volumes")
    delete_volumes(new_volumes)

    ### Start new instance
    
    print(bcolors.OKGREEN + "Re-start new instance: %s" % new_instance_id)

    ec2_client.start_instances(
        InstanceIds=[
            new_instance_id,
        ],
        DryRun=dry_run
    )
    
    wait_instance_ready(new_instance_id, 'running')

    print(bcolors.OKGREEN + "New instance is running: %s" % new_instance_id)

def get_instance(instance_id):
    try:
        response = ec2_client.describe_instances(
            InstanceIds=instance_id
        )

        if 'Reservations' in response:
            for reservation in response['Reservations']:
                if 'Instances' not in reservation:
                    raise Exception ('No Instances found')

                return reservation['Instances']
            
    except Exception as e:
        print(bcolors.FAIL + "error: %s" % e)
    
def terminate_instance(instance_id):
    print(bcolors.WARNING + "Terminating: %s" % (instance_id))

    ec2_client.terminate_instances(
        InstanceIds=[
            instance_id
        ],
        DryRun=dry_run
    )

    wait_instance_ready(instance_id, 'terminated')

    print(bcolors.WARNING + "Terminated: %s" % (instance_id))

def stop_instance(instance_id):
    print(bcolors.WARNING + "Stopping: %s" % (instance_id))

    ec2_client.stop_instances(
        InstanceIds=[
            instance_id
        ],
        DryRun=dry_run
    )
    
    wait_instance_ready(instance_id, 'stopped')

    print(bcolors.WARNING + "Stopped: %s" % (instance_id))

def get_instance_state(instance_id):
    describe_instances_response = ec2_client.describe_instances(
        InstanceIds=[
            instance_id
        ]
    )

    for instance in describe_instances_response['Reservations'][0]['Instances']:
        return instance['State']['Name']

def wait_instance_ready(instance_id, desired_status):
    while True:
        print(bcolors.WARNING + "Now waiting for status: %s of instance: %s " % (desired_status, instance_id))

        describe_instances_response = ec2_client.describe_instances(
            InstanceIds=[
                instance_id
            ]
        )
        ready = True
        for instance in describe_instances_response['Reservations'][0]['Instances']:
            if instance['State']['Name'] != desired_status:
                ready = False
        if ready:
            return
        sleep(5)

def delete_volumes(volumes_result):
    for volume in volumes_result:
        print(bcolors.WARNING + "Deleting volumes: %s " % volume['volume_id'])
        ec2_client.delete_volume(
            VolumeId=volume['volume_id'],
            DryRun=dry_run
        )

def attach_volumes(instance_id, volume_config):
    print(bcolors.WARNING + "Attaching volumes to: %s" % instance_id)
    for volume in volume_config:
        ec2_client.attach_volume(
            Device=volume['device_name'],
            InstanceId=instance_id,
            VolumeId=volume['volume_id']
        )
    
    while True:
        print(bcolors.WARNING + "Waiting for attaching volumes to: %s" % instance_id)
        all_attached = True
        volume_ids = []
        for volume in volume_config:
            volume_ids.append(volume['volume_id'])
        
        describe_volumes_response = ec2_client.describe_volumes(
            VolumeIds=volume_ids
        )
        for volume in describe_volumes_response['Volumes']:
            if volume['State'] != 'in-use':
                all_attached = False
                sleep(5)
        if all_attached:
            break

def detach_volumes(instance_id, block_config):
    print(bcolors.WARNING + "Detaching volumes from: %s" % instance_id)

    for volume in block_config:
        ec2_client.detach_volume(
            VolumeId=volume['volume_id']   
        )

    while True:
        print(bcolors.WARNING + "Waiting for detaching volumes from: %s" % instance_id)
        all_detached = True
        volume_ids = []
        for volume in block_config:
            volume_ids.append(volume['volume_id'])
        
        if volume_ids:
            describe_volumes_response = ec2_client.describe_volumes(
                VolumeIds=volume_ids
            )
            for volume in describe_volumes_response['Volumes']:            
                if volume['State'] != 'available':
                    all_detached = False
                    sleep(5)
            if all_detached:
                break
        else:
            break

def build_block_config(block_instance):
    volumes_result = []

    block_device_mappings = block_instance['BlockDeviceMappings']

    for bdm in block_device_mappings:
        if bdm['Ebs']['Status'] == 'attached':
            volume_id = bdm['Ebs']['VolumeId']
            device_name = bdm['DeviceName']

            volumes = ec2_client.describe_volumes(
                VolumeIds=[volume_id]
            )
            volume = volumes['Volumes'][0]

            volume_size = volume['Size']
            volume_type = volume['VolumeType']
            encrypted = volume['Encrypted']

            if 'KmsKeyId' in volume:
                kms_id = volume['KmsKeyId']
            else:
                kms_id = None

            if volume['VolumeType'] == 'io1':
                volume_iops = volume['Iops']
            else:
                volume_iops = None

            volumes_result.append({"volume_id": volume_id, 
                "device_name": device_name,
                "volume_size": volume_size,
                "volume_type": volume_type,
                "encrypted": encrypted,
                "kms_id": kms_id,
                "volume_iops": volume_iops})

    return volumes_result

def save_instance_details(instance):
    table = dynamodb.Table('instanceConverter')

    instance_id = instance['InstanceId']
    serializedInstance = pickle.dumps(instance)

    block_config = build_block_config(instance)
    serializedVolumes = pickle.dumps(block_config)

    table.put_item(
        Item={
            'instanceId': instance_id,
            'instanceData': serializedInstance,
            'instanceVolumes': serializedVolumes
        }
    )

    print(bcolors.OKGREEN + "INFO: Instance data saved")

def get_instance_details(instance_id, dimension='instanceData'):
    global region

    table = dynamodb.Table('instanceConverter')

    try:
        response = table.get_item(
            Key={
                'instanceId': instance_id
            }
        )
    except ClientError as e:
        print(bcolors.FAIL +  e.response['Error']['Message'])
    else:
        if 'Item' in response:
            item = response['Item']
            if dimension in item:
                binary_instance = item[dimension]
                dimension_data = pickle.loads(binary_instance.value)
                
                return dimension_data

def main():
    parser = argparse.ArgumentParser(description='Re-create an EC2 instance')

    parser.add_argument('--source-instance-ids', nargs='+', default=[], required=True, help='IDs of EC2 instances as source')
    parser.add_argument('--target-ami-id', nargs='?', default='', required=True, help='Specify target AMI' )
    parser.add_argument('--tenancy', nargs='?', default='', required=False, help='Specify target AMI' )
    parser.add_argument('--region', nargs='?', default='', required=False, help='Region to target')
    parser.add_argument('--dry-run', default=False, help='Option of dry run, not tested yet...')
    args = parser.parse_args()
    
    global dry_run
    global region
    global target_ami
    global tenancy

    global ec2_client
    global dynamodb

    if args.dry_run:
        dry_run = args.dry_run

    if args.region:
        region = args.region
        ec2_client = boto3.client('ec2', region_name=region)
        dynamodb = boto3.resource('dynamodb', region_name=region)

    if args.target_ami_id:
        target_ami = args.target_ami_id

    if args.tenancy:
        tenancy = args.tenancy
    
    recreate_instances(
        source_instance_ids=args.source_instance_ids
        # tenancy=args.tenancy
    )


if __name__ == "__main__":
    main()
