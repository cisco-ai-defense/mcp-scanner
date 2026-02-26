from mcp.server.fastmcp import FastMCP
from typing import Dict, List, Optional, Any
import json
from datetime import datetime

mcp = FastMCP("Azure Cloud Services Tools")

# Azure Virtual Machines (20 tools)

@mcp.tool()
def azure_create_vm(vm_name: str, resource_group: str, location: str = "East US", vm_size: str = "Standard_B1s", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create an Azure Virtual Machine"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}",
        "name": vm_name,
        "type": "Microsoft.Compute/virtualMachines",
        "location": location,
        "properties": {
            "vmId": "vm-12345",
            "hardwareProfile": {"vmSize": vm_size},
            "provisioningState": "Creating",
            "osProfile": {"computerName": vm_name, "adminUsername": "azureuser"},
            "storageProfile": {"osDisk": {"osType": "Linux", "diskSizeGB": 30}},
            "networkProfile": {"networkInterfaces": [{"id": f"nic-{vm_name}"}]}
        }
    }

@mcp.tool()
def azure_get_vm(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Virtual Machine details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}",
        "name": vm_name,
        "type": "Microsoft.Compute/virtualMachines",
        "location": "East US",
        "properties": {
            "vmId": "vm-12345",
            "hardwareProfile": {"vmSize": "Standard_B1s"},
            "provisioningState": "Succeeded",
            "powerState": "VM running",
            "osProfile": {"computerName": vm_name, "adminUsername": "azureuser"}
        }
    }

@mcp.tool()
def azure_start_vm(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Start an Azure Virtual Machine"""
    return {
        "status": "Accepted",
        "operation": "start",
        "vm_name": vm_name,
        "resource_group": resource_group,
        "message": "VM start operation initiated"
    }

@mcp.tool()
def azure_stop_vm(vm_name: str, resource_group: str, deallocate: bool = True, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Stop an Azure Virtual Machine"""
    return {
        "status": "Accepted",
        "operation": "stop" if not deallocate else "deallocate",
        "vm_name": vm_name,
        "resource_group": resource_group,
        "message": f"VM {'deallocate' if deallocate else 'stop'} operation initiated"
    }

@mcp.tool()
def azure_restart_vm(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Restart an Azure Virtual Machine"""
    return {
        "status": "Accepted",
        "operation": "restart",
        "vm_name": vm_name,
        "resource_group": resource_group,
        "message": "VM restart operation initiated"
    }

@mcp.tool()
def azure_delete_vm(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete an Azure Virtual Machine"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "vm_name": vm_name,
        "resource_group": resource_group,
        "message": "VM deletion initiated"
    }

@mcp.tool()
def azure_list_vms(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Virtual Machines"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
                "name": "vm1",
                "type": "Microsoft.Compute/virtualMachines",
                "location": "East US",
                "properties": {"provisioningState": "Succeeded", "powerState": "VM running"}
            },
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm2",
                "name": "vm2",
                "type": "Microsoft.Compute/virtualMachines",
                "location": "West US",
                "properties": {"provisioningState": "Succeeded", "powerState": "VM stopped"}
            }
        ]
    }

@mcp.tool()
def azure_resize_vm(vm_name: str, resource_group: str, new_size: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Resize an Azure Virtual Machine"""
    return {
        "status": "Accepted",
        "operation": "resize",
        "vm_name": vm_name,
        "resource_group": resource_group,
        "old_size": "Standard_B1s",
        "new_size": new_size,
        "message": "VM resize operation initiated"
    }

@mcp.tool()
def azure_get_vm_sizes(location: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get available VM sizes for a location"""
    return {
        "value": [
            {"name": "Standard_B1s", "numberOfCores": 1, "memoryInMB": 1024, "maxDataDiskCount": 2},
            {"name": "Standard_B2s", "numberOfCores": 2, "memoryInMB": 4096, "maxDataDiskCount": 4},
            {"name": "Standard_D2s_v3", "numberOfCores": 2, "memoryInMB": 8192, "maxDataDiskCount": 4},
            {"name": "Standard_D4s_v3", "numberOfCores": 4, "memoryInMB": 16384, "maxDataDiskCount": 8}
        ]
    }

@mcp.tool()
def azure_create_vm_image(vm_name: str, resource_group: str, image_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create an image from Azure VM"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/images/{image_name}",
        "name": image_name,
        "type": "Microsoft.Compute/images",
        "location": "East US",
        "properties": {
            "sourceVirtualMachine": {"id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"},
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_vm_extensions(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get VM extensions"""
    return {
        "value": [
            {
                "name": "CustomScript",
                "type": "Microsoft.Compute/virtualMachines/extensions",
                "properties": {
                    "publisher": "Microsoft.Azure.Extensions",
                    "type": "CustomScript",
                    "typeHandlerVersion": "2.1",
                    "provisioningState": "Succeeded"
                }
            }
        ]
    }

@mcp.tool()
def azure_install_vm_extension(vm_name: str, resource_group: str, extension_name: str, publisher: str, extension_type: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Install VM extension"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/extensions/{extension_name}",
        "name": extension_name,
        "type": "Microsoft.Compute/virtualMachines/extensions",
        "properties": {
            "publisher": publisher,
            "type": extension_type,
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_vm_metrics(vm_name: str, resource_group: str, metric_names: List[str], api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get VM performance metrics"""
    return {
        "value": [
            {
                "name": {"value": "Percentage CPU", "localizedValue": "Percentage CPU"},
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2024-01-01T12:00:00Z", "average": 25.5},
                            {"timeStamp": "2024-01-01T12:05:00Z", "average": 30.2}
                        ]
                    }
                ]
            }
        ]
    }

@mcp.tool()
def azure_create_vm_snapshot(vm_name: str, resource_group: str, snapshot_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create VM disk snapshot"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Compute/snapshots/{snapshot_name}",
        "name": snapshot_name,
        "type": "Microsoft.Compute/snapshots",
        "location": "East US",
        "properties": {
            "creationData": {"createOption": "Copy"},
            "provisioningState": "Creating",
            "diskSizeGB": 30
        }
    }

@mcp.tool()
def azure_attach_disk_to_vm(vm_name: str, resource_group: str, disk_name: str, lun: int, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Attach disk to VM"""
    return {
        "status": "Accepted",
        "operation": "attach_disk",
        "vm_name": vm_name,
        "disk_name": disk_name,
        "lun": lun,
        "message": "Disk attachment initiated"
    }

@mcp.tool()
def azure_detach_disk_from_vm(vm_name: str, resource_group: str, disk_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Detach disk from VM"""
    return {
        "status": "Accepted",
        "operation": "detach_disk",
        "vm_name": vm_name,
        "disk_name": disk_name,
        "message": "Disk detachment initiated"
    }

@mcp.tool()
def azure_get_vm_console_output(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get VM boot diagnostics console output"""
    return {
        "output": "Linux version 5.4.0-1043-azure (buildd@lgw01-amd64-038) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #45~20.04.1-Ubuntu SMP Mon Apr 5 09:57:56 UTC 2021\nCommand line: BOOT_IMAGE=/boot/vmlinuz-5.4.0-1043-azure root=PARTUUID=12345678-1234-1234-1234-123456789abc ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300"
    }

@mcp.tool()
def azure_enable_vm_backup(vm_name: str, resource_group: str, vault_name: str, policy_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Enable backup for VM"""
    return {
        "status": "Accepted",
        "operation": "enable_backup",
        "vm_name": vm_name,
        "vault_name": vault_name,
        "policy_name": policy_name,
        "message": "VM backup configuration initiated"
    }

@mcp.tool()
def azure_get_vm_backup_status(vm_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get VM backup status"""
    return {
        "vm_name": vm_name,
        "backup_enabled": True,
        "last_backup": "2024-01-01T02:00:00Z",
        "backup_policy": "DailyPolicy",
        "recovery_points": 7,
        "backup_status": "Healthy"
    }

# Azure Storage Services (30 tools)

@mcp.tool()
def azure_create_storage_account(account_name: str, resource_group: str, location: str = "East US", sku: str = "Standard_LRS", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Storage Account"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}",
        "name": account_name,
        "type": "Microsoft.Storage/storageAccounts",
        "location": location,
        "sku": {"name": sku, "tier": "Standard"},
        "kind": "StorageV2",
        "properties": {
            "provisioningState": "Creating",
            "primaryEndpoints": {
                "blob": f"https://{account_name}.blob.core.windows.net/",
                "file": f"https://{account_name}.file.core.windows.net/",
                "queue": f"https://{account_name}.queue.core.windows.net/"
            }
        }
    }

@mcp.tool()
def azure_get_storage_account(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Storage Account details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}",
        "name": account_name,
        "type": "Microsoft.Storage/storageAccounts",
        "location": "East US",
        "sku": {"name": "Standard_LRS", "tier": "Standard"},
        "kind": "StorageV2",
        "properties": {
            "provisioningState": "Succeeded",
            "creationTime": "2024-01-01T12:00:00Z",
            "primaryLocation": "East US",
            "statusOfPrimary": "available"
        }
    }

@mcp.tool()
def azure_list_storage_accounts(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Storage Accounts"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                "name": "storage1",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "East US",
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2"
            }
        ]
    }

@mcp.tool()
def azure_delete_storage_account(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure Storage Account"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "account_name": account_name,
        "resource_group": resource_group,
        "message": "Storage account deletion initiated"
    }

@mcp.tool()
def azure_create_blob_container(account_name: str, container_name: str, public_access: str = "None", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Blob Storage container"""
    return {
        "name": container_name,
        "properties": {
            "lastModified": datetime.now().isoformat() + "Z",
            "etag": "0x8D123456789ABCD",
            "publicAccess": public_access,
            "leaseStatus": "unlocked",
            "leaseState": "available"
        }
    }

@mcp.tool()
def azure_list_blob_containers(account_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Blob Storage containers"""
    return {
        "value": [
            {
                "name": "container1",
                "properties": {
                    "lastModified": "2024-01-01T12:00:00Z",
                    "etag": "0x8D123456789ABCD",
                    "publicAccess": "None",
                    "leaseStatus": "unlocked"
                }
            },
            {
                "name": "container2",
                "properties": {
                    "lastModified": "2024-01-01T11:00:00Z",
                    "etag": "0x8D123456789ABCE",
                    "publicAccess": "Blob",
                    "leaseStatus": "unlocked"
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_blob_container(account_name: str, container_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Blob Storage container"""
    return {
        "status": "Accepted",
        "operation": "delete_container",
        "account_name": account_name,
        "container_name": container_name,
        "message": "Container deletion initiated"
    }

@mcp.tool()
def azure_upload_blob(account_name: str, container_name: str, blob_name: str, content_type: str = "application/octet-stream", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Upload blob to container"""
    return {
        "name": blob_name,
        "properties": {
            "lastModified": datetime.now().isoformat() + "Z",
            "etag": "0x8D123456789ABCD",
            "contentLength": 1024,
            "contentType": content_type,
            "blobType": "BlockBlob"
        }
    }

@mcp.tool()
def azure_list_blobs(account_name: str, container_name: str, prefix: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List blobs in container"""
    return {
        "value": [
            {
                "name": "file1.txt",
                "properties": {
                    "lastModified": "2024-01-01T12:00:00Z",
                    "etag": "0x8D123456789ABCD",
                    "contentLength": 1024,
                    "contentType": "text/plain",
                    "blobType": "BlockBlob"
                }
            },
            {
                "name": "image1.jpg",
                "properties": {
                    "lastModified": "2024-01-01T11:30:00Z",
                    "etag": "0x8D123456789ABCE",
                    "contentLength": 2048,
                    "contentType": "image/jpeg",
                    "blobType": "BlockBlob"
                }
            }
        ]
    }

@mcp.tool()
def azure_get_blob_properties(account_name: str, container_name: str, blob_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get blob properties"""
    return {
        "name": blob_name,
        "properties": {
            "lastModified": "2024-01-01T12:00:00Z",
            "etag": "0x8D123456789ABCD",
            "contentLength": 1024,
            "contentType": "text/plain",
            "blobType": "BlockBlob",
            "leaseStatus": "unlocked",
            "leaseState": "available",
            "serverEncrypted": True
        }
    }

@mcp.tool()
def azure_delete_blob(account_name: str, container_name: str, blob_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete blob"""
    return {
        "status": "Accepted",
        "operation": "delete_blob",
        "account_name": account_name,
        "container_name": container_name,
        "blob_name": blob_name,
        "message": "Blob deletion completed"
    }

@mcp.tool()
def azure_copy_blob(source_account: str, source_container: str, source_blob: str, dest_account: str, dest_container: str, dest_blob: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Copy blob between containers"""
    return {
        "status": "Accepted",
        "operation": "copy_blob",
        "source": f"{source_account}/{source_container}/{source_blob}",
        "destination": f"{dest_account}/{dest_container}/{dest_blob}",
        "copyId": "copy-12345",
        "copyStatus": "pending"
    }

@mcp.tool()
def azure_set_blob_tier(account_name: str, container_name: str, blob_name: str, tier: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Set blob access tier"""
    return {
        "status": "Accepted",
        "operation": "set_blob_tier",
        "blob_name": blob_name,
        "tier": tier,
        "message": f"Blob tier changed to {tier}"
    }

@mcp.tool()
def azure_create_file_share(account_name: str, share_name: str, quota: int = 5120, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure File Share"""
    return {
        "name": share_name,
        "properties": {
            "lastModified": datetime.now().isoformat() + "Z",
            "etag": "0x8D123456789ABCD",
            "quota": quota,
            "shareUsageBytes": 0
        }
    }

@mcp.tool()
def azure_list_file_shares(account_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure File Shares"""
    return {
        "value": [
            {
                "name": "share1",
                "properties": {
                    "lastModified": "2024-01-01T12:00:00Z",
                    "etag": "0x8D123456789ABCD",
                    "quota": 5120,
                    "shareUsageBytes": 1024
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_file_share(account_name: str, share_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure File Share"""
    return {
        "status": "Accepted",
        "operation": "delete_share",
        "account_name": account_name,
        "share_name": share_name,
        "message": "File share deletion initiated"
    }

@mcp.tool()
def azure_upload_file(account_name: str, share_name: str, file_path: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Upload file to Azure File Share"""
    return {
        "name": file_path.split('/')[-1],
        "properties": {
            "lastModified": datetime.now().isoformat() + "Z",
            "etag": "0x8D123456789ABCD",
            "contentLength": 2048
        }
    }

@mcp.tool()
def azure_list_files(account_name: str, share_name: str, directory_path: str = "", api_token: Optional[str] = None) -> Dict[str, Any]:
    """List files in Azure File Share"""
    return {
        "value": [
            {
                "name": "document.txt",
                "properties": {
                    "lastModified": "2024-01-01T12:00:00Z",
                    "etag": "0x8D123456789ABCD",
                    "contentLength": 1024
                }
            },
            {
                "name": "subfolder",
                "properties": {
                    "lastModified": "2024-01-01T11:00:00Z",
                    "etag": "0x8D123456789ABCE",
                    "isDirectory": True
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_file(account_name: str, share_name: str, file_path: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete file from Azure File Share"""
    return {
        "status": "Accepted",
        "operation": "delete_file",
        "account_name": account_name,
        "share_name": share_name,
        "file_path": file_path,
        "message": "File deletion completed"
    }

@mcp.tool()
def azure_create_queue(account_name: str, queue_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Storage Queue"""
    return {
        "name": queue_name,
        "metadata": {},
        "approximateMessageCount": 0
    }

@mcp.tool()
def azure_list_queues(account_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Storage Queues"""
    return {
        "value": [
            {
                "name": "queue1",
                "metadata": {},
                "approximateMessageCount": 5
            },
            {
                "name": "queue2",
                "metadata": {},
                "approximateMessageCount": 0
            }
        ]
    }

@mcp.tool()
def azure_send_queue_message(account_name: str, queue_name: str, message_text: str, visibility_timeout: int = 30, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Send message to Azure Storage Queue"""
    return {
        "messageId": "msg-12345",
        "insertionTime": datetime.now().isoformat() + "Z",
        "expirationTime": (datetime.now().timestamp() + 604800),  # 7 days
        "popReceipt": "receipt-12345",
        "timeNextVisible": (datetime.now().timestamp() + visibility_timeout)
    }

@mcp.tool()
def azure_receive_queue_messages(account_name: str, queue_name: str, num_messages: int = 1, visibility_timeout: int = 30, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Receive messages from Azure Storage Queue"""
    return {
        "value": [
            {
                "messageId": "msg-12345",
                "messageText": "Hello, World!",
                "insertionTime": "2024-01-01T12:00:00Z",
                "expirationTime": "2024-01-08T12:00:00Z",
                "popReceipt": "receipt-12345",
                "timeNextVisible": "2024-01-01T12:30:00Z",
                "dequeueCount": 1
            }
        ]
    }

@mcp.tool()
def azure_delete_queue_message(account_name: str, queue_name: str, message_id: str, pop_receipt: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete message from Azure Storage Queue"""
    return {
        "status": "Accepted",
        "operation": "delete_message",
        "message_id": message_id,
        "message": "Message deleted successfully"
    }

@mcp.tool()
def azure_clear_queue(account_name: str, queue_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Clear all messages from Azure Storage Queue"""
    return {
        "status": "Accepted",
        "operation": "clear_queue",
        "queue_name": queue_name,
        "message": "All messages cleared from queue"
    }

@mcp.tool()
def azure_delete_queue(account_name: str, queue_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure Storage Queue"""
    return {
        "status": "Accepted",
        "operation": "delete_queue",
        "account_name": account_name,
        "queue_name": queue_name,
        "message": "Queue deletion completed"
    }

@mcp.tool()
def azure_get_storage_account_keys(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Storage Account access keys"""
    return {
        "keys": [
            {
                "keyName": "key1",
                "value": "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ==",
                "permissions": "Full"
            },
            {
                "keyName": "key2",
                "value": "ZYXWVUTSRQPONMLKJIHGFEDCBA0987654321zyxwvutsrqponmlkjihgfedcba==",
                "permissions": "Full"
            }
        ]
    }

@mcp.tool()
def azure_regenerate_storage_key(account_name: str, resource_group: str, key_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Regenerate Storage Account access key"""
    return {
        "keys": [
            {
                "keyName": key_name,
                "value": "newkey1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV==",
                "permissions": "Full"
            }
        ]
    }

# Azure Networking Services (30 tools)

@mcp.tool()
def azure_create_vnet(vnet_name: str, resource_group: str, location: str = "East US", address_space: str = "10.0.0.0/16", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Virtual Network"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}",
        "name": vnet_name,
        "type": "Microsoft.Network/virtualNetworks",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "addressSpace": {"addressPrefixes": [address_space]},
            "subnets": [],
            "enableDdosProtection": False
        }
    }

@mcp.tool()
def azure_get_vnet(vnet_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Virtual Network details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}",
        "name": vnet_name,
        "type": "Microsoft.Network/virtualNetworks",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
            "subnets": [
                {
                    "name": "default",
                    "properties": {
                        "addressPrefix": "10.0.0.0/24",
                        "provisioningState": "Succeeded"
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_list_vnets(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Virtual Networks"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1",
                "name": "vnet1",
                "type": "Microsoft.Network/virtualNetworks",
                "location": "East US",
                "properties": {
                    "provisioningState": "Succeeded",
                    "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_vnet(vnet_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure Virtual Network"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "vnet_name": vnet_name,
        "resource_group": resource_group,
        "message": "Virtual network deletion initiated"
    }

@mcp.tool()
def azure_create_subnet(vnet_name: str, subnet_name: str, resource_group: str, address_prefix: str = "10.0.1.0/24", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create subnet in Azure Virtual Network"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/{subnet_name}",
        "name": subnet_name,
        "type": "Microsoft.Network/virtualNetworks/subnets",
        "properties": {
            "provisioningState": "Creating",
            "addressPrefix": address_prefix,
            "networkSecurityGroup": None,
            "routeTable": None
        }
    }

@mcp.tool()
def azure_get_subnet(vnet_name: str, subnet_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure subnet details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/{subnet_name}",
        "name": subnet_name,
        "type": "Microsoft.Network/virtualNetworks/subnets",
        "properties": {
            "provisioningState": "Succeeded",
            "addressPrefix": "10.0.1.0/24",
            "availableIpAddressCount": 251,
            "networkSecurityGroup": None
        }
    }

@mcp.tool()
def azure_list_subnets(vnet_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List subnets in Azure Virtual Network"""
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/default",
                "name": "default",
                "properties": {
                    "provisioningState": "Succeeded",
                    "addressPrefix": "10.0.0.0/24",
                    "availableIpAddressCount": 251
                }
            },
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/subnet1",
                "name": "subnet1",
                "properties": {
                    "provisioningState": "Succeeded",
                    "addressPrefix": "10.0.1.0/24",
                    "availableIpAddressCount": 251
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_subnet(vnet_name: str, subnet_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure subnet"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "subnet_name": subnet_name,
        "vnet_name": vnet_name,
        "message": "Subnet deletion initiated"
    }

@mcp.tool()
def azure_create_nsg(nsg_name: str, resource_group: str, location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Network Security Group"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}",
        "name": nsg_name,
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "securityRules": [],
            "defaultSecurityRules": [
                {
                    "name": "AllowVnetInBound",
                    "properties": {
                        "priority": 65000,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "*",
                        "sourcePortRange": "*",
                        "destinationPortRange": "*"
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_get_nsg(nsg_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Network Security Group details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}",
        "name": nsg_name,
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "securityRules": [
                {
                    "name": "SSH",
                    "properties": {
                        "priority": 1000,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*"
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_create_nsg_rule(nsg_name: str, rule_name: str, resource_group: str, priority: int, direction: str, access: str, protocol: str, source_port: str, dest_port: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Network Security Group rule"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}/securityRules/{rule_name}",
        "name": rule_name,
        "type": "Microsoft.Network/networkSecurityGroups/securityRules",
        "properties": {
            "provisioningState": "Creating",
            "priority": priority,
            "direction": direction,
            "access": access,
            "protocol": protocol,
            "sourcePortRange": source_port,
            "destinationPortRange": dest_port,
            "sourceAddressPrefix": "*",
            "destinationAddressPrefix": "*"
        }
    }

@mcp.tool()
def azure_delete_nsg_rule(nsg_name: str, rule_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Network Security Group rule"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "rule_name": rule_name,
        "nsg_name": nsg_name,
        "message": "NSG rule deletion initiated"
    }

@mcp.tool()
def azure_create_public_ip(ip_name: str, resource_group: str, location: str = "East US", allocation_method: str = "Dynamic", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Public IP Address"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{ip_name}",
        "name": ip_name,
        "type": "Microsoft.Network/publicIPAddresses",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "publicIPAllocationMethod": allocation_method,
            "publicIPAddressVersion": "IPv4",
            "idleTimeoutInMinutes": 4
        }
    }

@mcp.tool()
def azure_get_public_ip(ip_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Public IP Address details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{ip_name}",
        "name": ip_name,
        "type": "Microsoft.Network/publicIPAddresses",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "publicIPAllocationMethod": "Static",
            "publicIPAddressVersion": "IPv4",
            "ipAddress": "20.1.2.3",
            "idleTimeoutInMinutes": 4
        }
    }

@mcp.tool()
def azure_list_public_ips(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Public IP Addresses"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/ip1",
                "name": "ip1",
                "type": "Microsoft.Network/publicIPAddresses",
                "location": "East US",
                "properties": {
                    "provisioningState": "Succeeded",
                    "publicIPAllocationMethod": "Static",
                    "ipAddress": "20.1.2.3"
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_public_ip(ip_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure Public IP Address"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "ip_name": ip_name,
        "resource_group": resource_group,
        "message": "Public IP deletion initiated"
    }

@mcp.tool()
def azure_create_load_balancer(lb_name: str, resource_group: str, location: str = "East US", sku: str = "Standard", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Load Balancer"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/loadBalancers/{lb_name}",
        "name": lb_name,
        "type": "Microsoft.Network/loadBalancers",
        "location": location,
        "sku": {"name": sku},
        "properties": {
            "provisioningState": "Creating",
            "frontendIPConfigurations": [],
            "backendAddressPools": [],
            "loadBalancingRules": [],
            "probes": []
        }
    }

@mcp.tool()
def azure_get_load_balancer(lb_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Load Balancer details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/loadBalancers/{lb_name}",
        "name": lb_name,
        "type": "Microsoft.Network/loadBalancers",
        "location": "East US",
        "sku": {"name": "Standard"},
        "properties": {
            "provisioningState": "Succeeded",
            "frontendIPConfigurations": [
                {
                    "name": "frontend1",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "publicIPAddress": {"id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/lb-ip"}
                    }
                }
            ],
            "backendAddressPools": [{"name": "backend1"}]
        }
    }

@mcp.tool()
def azure_create_app_gateway(gw_name: str, resource_group: str, location: str = "East US", sku_name: str = "Standard_v2", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Application Gateway"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{gw_name}",
        "name": gw_name,
        "type": "Microsoft.Network/applicationGateways",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "sku": {"name": sku_name, "tier": "Standard_v2", "capacity": 2},
            "gatewayIPConfigurations": [],
            "frontendIPConfigurations": [],
            "frontendPorts": [],
            "backendAddressPools": [],
            "httpListeners": [],
            "requestRoutingRules": []
        }
    }

@mcp.tool()
def azure_get_app_gateway(gw_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Application Gateway details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{gw_name}",
        "name": gw_name,
        "type": "Microsoft.Network/applicationGateways",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "sku": {"name": "Standard_v2", "tier": "Standard_v2", "capacity": 2},
            "operationalState": "Running",
            "frontendIPConfigurations": [
                {
                    "name": "appGwPublicFrontendIp",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "publicIPAddress": {"id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/gw-ip"}
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_create_nic(nic_name: str, resource_group: str, subnet_id: str, location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Network Interface"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{nic_name}",
        "name": nic_name,
        "type": "Microsoft.Network/networkInterfaces",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "subnet": {"id": subnet_id},
                        "primary": True,
                        "privateIPAddressVersion": "IPv4"
                    }
                }
            ],
            "enableIPForwarding": False
        }
    }

@mcp.tool()
def azure_get_nic(nic_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Network Interface details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces/{nic_name}",
        "name": nic_name,
        "type": "Microsoft.Network/networkInterfaces",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "properties": {
                        "privateIPAllocationMethod": "Dynamic",
                        "privateIPAddress": "10.0.0.4",
                        "subnet": {"id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default"},
                        "primary": True
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_list_nics(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Network Interfaces"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1",
                "name": "nic1",
                "type": "Microsoft.Network/networkInterfaces",
                "location": "East US",
                "properties": {
                    "provisioningState": "Succeeded",
                    "ipConfigurations": [
                        {
                            "name": "ipconfig1",
                            "properties": {
                                "privateIPAddress": "10.0.0.4",
                                "privateIPAllocationMethod": "Dynamic"
                            }
                        }
                    ]
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_nic(nic_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete Azure Network Interface"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "nic_name": nic_name,
        "resource_group": resource_group,
        "message": "Network interface deletion initiated"
    }

@mcp.tool()
def azure_create_route_table(rt_name: str, resource_group: str, location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Route Table"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/routeTables/{rt_name}",
        "name": rt_name,
        "type": "Microsoft.Network/routeTables",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "routes": [],
            "disableBgpRoutePropagation": False
        }
    }

@mcp.tool()
def azure_create_route(rt_name: str, route_name: str, resource_group: str, address_prefix: str, next_hop_type: str, next_hop_ip: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create route in Azure Route Table"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/routeTables/{rt_name}/routes/{route_name}",
        "name": route_name,
        "type": "Microsoft.Network/routeTables/routes",
        "properties": {
            "provisioningState": "Creating",
            "addressPrefix": address_prefix,
            "nextHopType": next_hop_type,
            "nextHopIpAddress": next_hop_ip
        }
    }

@mcp.tool()
def azure_get_network_watcher(watcher_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Network Watcher details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkWatchers/{watcher_name}",
        "name": watcher_name,
        "type": "Microsoft.Network/networkWatchers",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_start_packet_capture(watcher_name: str, resource_group: str, vm_id: str, capture_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Start packet capture on VM"""
    return {
        "name": capture_name,
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Network/networkWatchers/{watcher_name}/packetCaptures/{capture_name}",
        "properties": {
            "provisioningState": "Creating",
            "target": vm_id,
            "bytesToCapturePerPacket": 0,
            "totalBytesPerSession": 1073741824,
            "timeLimitInSeconds": 18000
        }
    }

@mcp.tool()
def azure_test_connectivity(watcher_name: str, resource_group: str, source_vm: str, dest_address: str, dest_port: int, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Test network connectivity between resources"""
    return {
        "hops": [
            {
                "type": "Source",
                "id": source_vm,
                "address": "10.0.0.4",
                "resourceId": source_vm,
                "nextHopIds": ["hop1"]
            },
            {
                "type": "Internet",
                "id": "hop1",
                "address": dest_address,
                "nextHopIds": []
            }
        ],
        "connectionStatus": "Reachable",
        "avgLatencyInMs": 15,
        "minLatencyInMs": 12,
        "maxLatencyInMs": 18,
        "probesSent": 10,
        "probesFailed": 0
    }

# Azure Database Services (30 tools)

@mcp.tool()
def azure_create_sql_server(server_name: str, resource_group: str, location: str = "East US", admin_login: str = "sqladmin", admin_password: str = "Password123!", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure SQL Server"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.Sql/servers",
        "location": location,
        "properties": {
            "administratorLogin": admin_login,
            "version": "12.0",
            "state": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.database.windows.net",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_sql_server(server_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure SQL Server details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.Sql/servers",
        "location": "East US",
        "properties": {
            "administratorLogin": "sqladmin",
            "version": "12.0",
            "state": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.database.windows.net",
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_create_sql_database(server_name: str, db_name: str, resource_group: str, sku_name: str = "Basic", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure SQL Database"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}",
        "name": db_name,
        "type": "Microsoft.Sql/servers/databases",
        "location": "East US",
        "sku": {"name": sku_name, "tier": "Basic"},
        "properties": {
            "collation": "SQL_Latin1_General_CP1_CI_AS",
            "maxSizeBytes": 2147483648,
            "status": "Online",
            "creationDate": "2024-01-01T12:00:00Z",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_sql_database(server_name: str, db_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure SQL Database details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}",
        "name": db_name,
        "type": "Microsoft.Sql/servers/databases",
        "location": "East US",
        "sku": {"name": "Basic", "tier": "Basic"},
        "properties": {
            "collation": "SQL_Latin1_General_CP1_CI_AS",
            "maxSizeBytes": 2147483648,
            "status": "Online",
            "creationDate": "2024-01-01T12:00:00Z",
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_list_sql_databases(server_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure SQL Databases"""
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}/databases/master",
                "name": "master",
                "type": "Microsoft.Sql/servers/databases",
                "properties": {
                    "status": "Online",
                    "collation": "SQL_Latin1_General_CP1_CI_AS"
                }
            },
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}/databases/mydb",
                "name": "mydb",
                "type": "Microsoft.Sql/servers/databases",
                "properties": {
                    "status": "Online",
                    "collation": "SQL_Latin1_General_CP1_CI_AS"
                }
            }
        ]
    }

@mcp.tool()
def azure_scale_sql_database(server_name: str, db_name: str, resource_group: str, sku_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Scale Azure SQL Database"""
    return {
        "status": "Accepted",
        "operation": "scale_database",
        "database_name": db_name,
        "server_name": server_name,
        "new_sku": sku_name,
        "message": "Database scaling initiated"
    }

@mcp.tool()
def azure_backup_sql_database(server_name: str, db_name: str, resource_group: str, backup_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure SQL Database backup"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}/backups/{backup_name}",
        "name": backup_name,
        "type": "Microsoft.Sql/servers/databases/backups",
        "properties": {
            "backupType": "Full",
            "backupTime": datetime.now().isoformat() + "Z",
            "status": "Creating"
        }
    }

@mcp.tool()
def azure_restore_sql_database(server_name: str, source_db: str, target_db: str, resource_group: str, restore_point: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Restore Azure SQL Database"""
    return {
        "status": "Accepted",
        "operation": "restore_database",
        "source_database": source_db,
        "target_database": target_db,
        "restore_point": restore_point,
        "message": "Database restore initiated"
    }

@mcp.tool()
def azure_create_cosmos_account(account_name: str, resource_group: str, location: str = "East US", api_type: str = "Sql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Cosmos DB Account"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}",
        "name": account_name,
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "location": location,
        "properties": {
            "provisioningState": "Creating",
            "documentEndpoint": f"https://{account_name}.documents.azure.com:443/",
            "databaseAccountOfferType": "Standard",
            "consistencyPolicy": {
                "defaultConsistencyLevel": "Session"
            },
            "locations": [
                {
                    "locationName": location,
                    "failoverPriority": 0,
                    "isZoneRedundant": False
                }
            ]
        }
    }

@mcp.tool()
def azure_get_cosmos_account(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Cosmos DB Account details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}",
        "name": account_name,
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "location": "East US",
        "properties": {
            "provisioningState": "Succeeded",
            "documentEndpoint": f"https://{account_name}.documents.azure.com:443/",
            "databaseAccountOfferType": "Standard",
            "consistencyPolicy": {
                "defaultConsistencyLevel": "Session"
            },
            "readLocations": [
                {
                    "locationName": "East US",
                    "documentEndpoint": f"https://{account_name}-eastus.documents.azure.com:443/",
                    "provisioningState": "Succeeded"
                }
            ]
        }
    }

@mcp.tool()
def azure_create_cosmos_database(account_name: str, db_name: str, resource_group: str, throughput: int = 400, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Cosmos DB Database"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}/sqlDatabases/{db_name}",
        "name": db_name,
        "type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases",
        "properties": {
            "resource": {"id": db_name},
            "options": {"throughput": throughput},
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_create_cosmos_container(account_name: str, db_name: str, container_name: str, resource_group: str, partition_key: str, throughput: int = 400, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Cosmos DB Container"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}/sqlDatabases/{db_name}/containers/{container_name}",
        "name": container_name,
        "type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers",
        "properties": {
            "resource": {
                "id": container_name,
                "partitionKey": {
                    "paths": [f"/{partition_key}"],
                    "kind": "Hash"
                }
            },
            "options": {"throughput": throughput},
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_list_cosmos_databases(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure Cosmos DB Databases"""
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DocumentDB/databaseAccounts/{account_name}/sqlDatabases/db1",
                "name": "db1",
                "type": "Microsoft.DocumentDB/databaseAccounts/sqlDatabases",
                "properties": {
                    "resource": {"id": "db1"}
                }
            }
        ]
    }

@mcp.tool()
def azure_get_cosmos_keys(account_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Cosmos DB Account keys"""
    return {
        "primaryMasterKey": "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz==",
        "secondaryMasterKey": "ZYXWVUTSRQPONMLKJIHGFEDCBA0987654321zyxwvutsrqponmlkjihgfedcba0987654321ZYXWVUTSRQPONMLKJIHGFEDCBA==",
        "primaryReadonlyMasterKey": "readonly1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnop==",
        "secondaryReadonlyMasterKey": "readonly0987654321zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA0987654321zyxwvutsrqponmlk=="
    }

@mcp.tool()
def azure_create_mysql_server(server_name: str, resource_group: str, location: str = "East US", admin_login: str = "mysqladmin", admin_password: str = "Password123!", sku_name: str = "B_Gen5_1", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Database for MySQL server"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforMySQL/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.DBforMySQL/servers",
        "location": location,
        "sku": {"name": sku_name, "tier": "Basic", "capacity": 1},
        "properties": {
            "administratorLogin": admin_login,
            "version": "8.0",
            "sslEnforcement": "Enabled",
            "userVisibleState": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.mysql.database.azure.com",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_mysql_server(server_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Database for MySQL server details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforMySQL/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.DBforMySQL/servers",
        "location": "East US",
        "sku": {"name": "B_Gen5_1", "tier": "Basic", "capacity": 1},
        "properties": {
            "administratorLogin": "mysqladmin",
            "version": "8.0",
            "sslEnforcement": "Enabled",
            "userVisibleState": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.mysql.database.azure.com",
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_create_mysql_database(server_name: str, db_name: str, resource_group: str, charset: str = "utf8", collation: str = "utf8_general_ci", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create MySQL database"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforMySQL/servers/{server_name}/databases/{db_name}",
        "name": db_name,
        "type": "Microsoft.DBforMySQL/servers/databases",
        "properties": {
            "charset": charset,
            "collation": collation,
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_create_postgresql_server(server_name: str, resource_group: str, location: str = "East US", admin_login: str = "pgadmin", admin_password: str = "Password123!", sku_name: str = "B_Gen5_1", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Database for PostgreSQL server"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforPostgreSQL/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.DBforPostgreSQL/servers",
        "location": location,
        "sku": {"name": sku_name, "tier": "Basic", "capacity": 1},
        "properties": {
            "administratorLogin": admin_login,
            "version": "13",
            "sslEnforcement": "Enabled",
            "userVisibleState": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.postgres.database.azure.com",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_postgresql_server(server_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Database for PostgreSQL server details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforPostgreSQL/servers/{server_name}",
        "name": server_name,
        "type": "Microsoft.DBforPostgreSQL/servers",
        "location": "East US",
        "sku": {"name": "B_Gen5_1", "tier": "Basic", "capacity": 1},
        "properties": {
            "administratorLogin": "pgadmin",
            "version": "13",
            "sslEnforcement": "Enabled",
            "userVisibleState": "Ready",
            "fullyQualifiedDomainName": f"{server_name}.postgres.database.azure.com",
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_create_postgresql_database(server_name: str, db_name: str, resource_group: str, charset: str = "UTF8", collation: str = "English_United States.1252", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create PostgreSQL database"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.DBforPostgreSQL/servers/{server_name}/databases/{db_name}",
        "name": db_name,
        "type": "Microsoft.DBforPostgreSQL/servers/databases",
        "properties": {
            "charset": charset,
            "collation": collation,
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_create_firewall_rule(server_name: str, rule_name: str, resource_group: str, start_ip: str, end_ip: str, server_type: str = "sql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create database server firewall rule"""
    provider_map = {
        "sql": "Microsoft.Sql/servers",
        "mysql": "Microsoft.DBforMySQL/servers",
        "postgresql": "Microsoft.DBforPostgreSQL/servers"
    }
    
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/{provider_map[server_type]}/{server_name}/firewallRules/{rule_name}",
        "name": rule_name,
        "type": f"{provider_map[server_type]}/firewallRules",
        "properties": {
            "startIpAddress": start_ip,
            "endIpAddress": end_ip,
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_list_firewall_rules(server_name: str, resource_group: str, server_type: str = "sql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """List database server firewall rules"""
    provider_map = {
        "sql": "Microsoft.Sql/servers",
        "mysql": "Microsoft.DBforMySQL/servers",
        "postgresql": "Microsoft.DBforPostgreSQL/servers"
    }
    
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/{provider_map[server_type]}/{server_name}/firewallRules/AllowAll",
                "name": "AllowAll",
                "type": f"{provider_map[server_type]}/firewallRules",
                "properties": {
                    "startIpAddress": "0.0.0.0",
                    "endIpAddress": "255.255.255.255"
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_firewall_rule(server_name: str, rule_name: str, resource_group: str, server_type: str = "sql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete database server firewall rule"""
    return {
        "status": "Accepted",
        "operation": "delete",
        "rule_name": rule_name,
        "server_name": server_name,
        "server_type": server_type,
        "message": "Firewall rule deletion initiated"
    }

@mcp.tool()
def azure_get_database_metrics(server_name: str, resource_group: str, server_type: str = "sql", metric_names: List[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get database server performance metrics"""
    return {
        "value": [
            {
                "name": {"value": "cpu_percent", "localizedValue": "CPU percentage"},
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2024-01-01T12:00:00Z", "average": 25.5},
                            {"timeStamp": "2024-01-01T12:05:00Z", "average": 30.2}
                        ]
                    }
                ]
            },
            {
                "name": {"value": "memory_percent", "localizedValue": "Memory percentage"},
                "timeseries": [
                    {
                        "data": [
                            {"timeStamp": "2024-01-01T12:00:00Z", "average": 45.8},
                            {"timeStamp": "2024-01-01T12:05:00Z", "average": 48.1}
                        ]
                    }
                ]
            }
        ]
    }

@mcp.tool()
def azure_configure_database_backup(server_name: str, resource_group: str, retention_days: int = 7, geo_redundant: bool = False, server_type: str = "sql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Configure database backup settings"""
    return {
        "status": "Accepted",
        "operation": "configure_backup",
        "server_name": server_name,
        "retention_days": retention_days,
        "geo_redundant_backup": geo_redundant,
        "server_type": server_type,
        "message": "Backup configuration updated"
    }

@mcp.tool()
def azure_create_read_replica(source_server: str, replica_name: str, resource_group: str, location: str, server_type: str = "mysql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create database read replica"""
    provider_map = {
        "mysql": "Microsoft.DBforMySQL/servers",
        "postgresql": "Microsoft.DBforPostgreSQL/servers"
    }
    
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/{provider_map[server_type]}/{replica_name}",
        "name": replica_name,
        "type": provider_map[server_type],
        "location": location,
        "properties": {
            "createMode": "Replica",
            "sourceServerId": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/{provider_map[server_type]}/{source_server}",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_promote_read_replica(replica_name: str, resource_group: str, server_type: str = "mysql", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Promote read replica to standalone server"""
    return {
        "status": "Accepted",
        "operation": "promote_replica",
        "replica_name": replica_name,
        "server_type": server_type,
        "message": "Read replica promotion initiated"
    }

# Azure AI/ML and Security Services (30 tools)

@mcp.tool()
def azure_create_cognitive_service(service_name: str, resource_group: str, kind: str = "CognitiveServices", sku_name: str = "S0", location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Cognitive Services resource"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.CognitiveServices/accounts/{service_name}",
        "name": service_name,
        "type": "Microsoft.CognitiveServices/accounts",
        "location": location,
        "kind": kind,
        "sku": {"name": sku_name},
        "properties": {
            "provisioningState": "Creating",
            "endpoint": f"https://{service_name}.cognitiveservices.azure.com/",
            "customSubDomainName": service_name
        }
    }

@mcp.tool()
def azure_get_cognitive_service(service_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Cognitive Services resource details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.CognitiveServices/accounts/{service_name}",
        "name": service_name,
        "type": "Microsoft.CognitiveServices/accounts",
        "location": "East US",
        "kind": "CognitiveServices",
        "sku": {"name": "S0"},
        "properties": {
            "provisioningState": "Succeeded",
            "endpoint": f"https://{service_name}.cognitiveservices.azure.com/",
            "customSubDomainName": service_name
        }
    }

@mcp.tool()
def azure_get_cognitive_service_keys(service_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Cognitive Services API keys"""
    return {
        "key1": "abcdef1234567890abcdef1234567890",
        "key2": "fedcba0987654321fedcba0987654321"
    }

@mcp.tool()
def azure_regenerate_cognitive_service_key(service_name: str, resource_group: str, key_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Regenerate Cognitive Services API key"""
    return {
        "key1": "newkey1234567890abcdef1234567890" if key_name == "Key1" else "abcdef1234567890abcdef1234567890",
        "key2": "newfed0987654321fedcba0987654321" if key_name == "Key2" else "fedcba0987654321fedcba0987654321"
    }

@mcp.tool()
def azure_create_ml_workspace(workspace_name: str, resource_group: str, location: str = "East US", storage_account: str = None, key_vault: str = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Machine Learning workspace"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}",
        "name": workspace_name,
        "type": "Microsoft.MachineLearningServices/workspaces",
        "location": location,
        "properties": {
            "friendlyName": workspace_name,
            "description": "Azure ML workspace",
            "storageAccount": storage_account or f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/mlstorage",
            "keyVault": key_vault or f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/mlkeyvault",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_ml_workspace(workspace_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Machine Learning workspace details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}",
        "name": workspace_name,
        "type": "Microsoft.MachineLearningServices/workspaces",
        "location": "East US",
        "properties": {
            "friendlyName": workspace_name,
            "description": "Azure ML workspace",
            "workspaceId": "ws-12345",
            "discoveryUrl": f"https://{workspace_name}.api.azureml.ms/discovery",
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_create_ml_compute(workspace_name: str, compute_name: str, resource_group: str, vm_size: str = "Standard_DS3_v2", min_nodes: int = 0, max_nodes: int = 4, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure ML compute cluster"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}/computes/{compute_name}",
        "name": compute_name,
        "type": "Microsoft.MachineLearningServices/workspaces/computes",
        "properties": {
            "computeType": "AmlCompute",
            "provisioningState": "Creating",
            "properties": {
                "vmSize": vm_size,
                "scaleSettings": {
                    "minNodeCount": min_nodes,
                    "maxNodeCount": max_nodes
                }
            }
        }
    }

@mcp.tool()
def azure_list_ml_computes(workspace_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List Azure ML compute resources"""
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}/computes/cpu-cluster",
                "name": "cpu-cluster",
                "type": "Microsoft.MachineLearningServices/workspaces/computes",
                "properties": {
                    "computeType": "AmlCompute",
                    "provisioningState": "Succeeded"
                }
            }
        ]
    }

@mcp.tool()
def azure_create_ml_model(workspace_name: str, model_name: str, resource_group: str, model_path: str, description: str = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Register Azure ML model"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}/models/{model_name}",
        "name": model_name,
        "properties": {
            "description": description or "Registered model",
            "path": model_path,
            "version": 1,
            "createdTime": datetime.now().isoformat() + "Z",
            "framework": "scikit-learn"
        }
    }

@mcp.tool()
def azure_create_ml_endpoint(workspace_name: str, endpoint_name: str, resource_group: str, model_name: str, instance_type: str = "Standard_DS3_v2", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure ML online endpoint"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.MachineLearningServices/workspaces/{workspace_name}/onlineEndpoints/{endpoint_name}",
        "name": endpoint_name,
        "type": "Microsoft.MachineLearningServices/workspaces/onlineEndpoints",
        "properties": {
            "authMode": "Key",
            "provisioningState": "Creating",
            "scoringUri": f"https://{endpoint_name}.{workspace_name}.inference.ml.azure.com/score",
            "deployments": [
                {
                    "name": "default",
                    "model": model_name,
                    "instanceType": instance_type
                }
            ]
        }
    }

@mcp.tool()
def azure_create_key_vault(vault_name: str, resource_group: str, location: str = "East US", sku_name: str = "standard", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Key Vault"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{vault_name}",
        "name": vault_name,
        "type": "Microsoft.KeyVault/vaults",
        "location": location,
        "properties": {
            "sku": {"family": "A", "name": sku_name},
            "tenantId": "tenant-12345",
            "vaultUri": f"https://{vault_name}.vault.azure.net/",
            "enabledForDeployment": False,
            "enabledForTemplateDeployment": False,
            "enabledForDiskEncryption": False,
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_key_vault(vault_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Key Vault details"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.KeyVault/vaults/{vault_name}",
        "name": vault_name,
        "type": "Microsoft.KeyVault/vaults",
        "location": "East US",
        "properties": {
            "sku": {"family": "A", "name": "standard"},
            "tenantId": "tenant-12345",
            "vaultUri": f"https://{vault_name}.vault.azure.net/",
            "enabledForDeployment": False,
            "provisioningState": "Succeeded"
        }
    }

@mcp.tool()
def azure_create_key_vault_secret(vault_name: str, secret_name: str, secret_value: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create secret in Azure Key Vault"""
    return {
        "id": f"https://{vault_name}.vault.azure.net/secrets/{secret_name}",
        "attributes": {
            "enabled": True,
            "created": int(datetime.now().timestamp()),
            "updated": int(datetime.now().timestamp())
        },
        "value": secret_value
    }

@mcp.tool()
def azure_get_key_vault_secret(vault_name: str, secret_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get secret from Azure Key Vault"""
    return {
        "id": f"https://{vault_name}.vault.azure.net/secrets/{secret_name}",
        "attributes": {
            "enabled": True,
            "created": 1640995200,
            "updated": 1640995200
        },
        "value": "secret-value-123"
    }

@mcp.tool()
def azure_list_key_vault_secrets(vault_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """List secrets in Azure Key Vault"""
    return {
        "value": [
            {
                "id": f"https://{vault_name}.vault.azure.net/secrets/secret1",
                "attributes": {
                    "enabled": True,
                    "created": 1640995200,
                    "updated": 1640995200
                }
            },
            {
                "id": f"https://{vault_name}.vault.azure.net/secrets/secret2",
                "attributes": {
                    "enabled": True,
                    "created": 1640995100,
                    "updated": 1640995100
                }
            }
        ]
    }

@mcp.tool()
def azure_delete_key_vault_secret(vault_name: str, secret_name: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Delete secret from Azure Key Vault"""
    return {
        "id": f"https://{vault_name}.vault.azure.net/secrets/{secret_name}",
        "deletedDate": int(datetime.now().timestamp()),
        "scheduledPurgeDate": int(datetime.now().timestamp()) + 7776000,  # 90 days
        "recoveryId": f"https://{vault_name}.vault.azure.net/deletedsecrets/{secret_name}"
    }

@mcp.tool()
def azure_create_key_vault_key(vault_name: str, key_name: str, key_type: str = "RSA", key_size: int = 2048, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create key in Azure Key Vault"""
    return {
        "key": {
            "kid": f"https://{vault_name}.vault.azure.net/keys/{key_name}",
            "kty": key_type,
            "key_ops": ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"],
            "n": "base64-encoded-key-modulus",
            "e": "AQAB"
        },
        "attributes": {
            "enabled": True,
            "created": int(datetime.now().timestamp()),
            "updated": int(datetime.now().timestamp())
        }
    }

@mcp.tool()
def azure_get_security_center_alerts(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Security Center alerts"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/providers/Microsoft.Security/alerts/alert1",
                "name": "alert1",
                "type": "Microsoft.Security/alerts",
                "properties": {
                    "alertDisplayName": "Suspicious PowerShell Activity",
                    "alertType": "VM_SuspiciousPowerShellActivity",
                    "severity": "High",
                    "state": "Active",
                    "timeGeneratedUtc": "2024-01-01T12:00:00Z",
                    "description": "Suspicious PowerShell activity detected on virtual machine"
                }
            }
        ]
    }

@mcp.tool()
def azure_get_security_center_recommendations(resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Security Center recommendations"""
    return {
        "value": [
            {
                "id": "/subscriptions/sub123/providers/Microsoft.Security/assessments/rec1",
                "name": "rec1",
                "type": "Microsoft.Security/assessments",
                "properties": {
                    "displayName": "Enable disk encryption",
                    "status": {
                        "code": "Unhealthy",
                        "severity": "High"
                    },
                    "resourceDetails": {
                        "source": "Azure",
                        "id": "/subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
                    }
                }
            }
        ]
    }

@mcp.tool()
def azure_enable_security_center_policy(policy_name: str, resource_group: Optional[str] = None, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Enable Azure Security Center policy"""
    return {
        "status": "Accepted",
        "operation": "enable_policy",
        "policy_name": policy_name,
        "resource_group": resource_group,
        "message": "Security policy enabled"
    }

@mcp.tool()
def azure_create_sentinel_workspace(workspace_name: str, resource_group: str, location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Sentinel workspace"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}",
        "name": workspace_name,
        "type": "Microsoft.OperationalInsights/workspaces",
        "location": location,
        "properties": {
            "sku": {"name": "pergb2018"},
            "retentionInDays": 30,
            "workspaceCapping": {"dailyQuotaGb": 1},
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_sentinel_incidents(workspace_name: str, resource_group: str, api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Azure Sentinel incidents"""
    return {
        "value": [
            {
                "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents/incident1",
                "name": "incident1",
                "type": "Microsoft.SecurityInsights/incidents",
                "properties": {
                    "title": "Suspicious login activity",
                    "description": "Multiple failed login attempts detected",
                    "severity": "High",
                    "status": "New",
                    "createdTimeUtc": "2024-01-01T12:00:00Z",
                    "lastModifiedTimeUtc": "2024-01-01T12:00:00Z"
                }
            }
        ]
    }

@mcp.tool()
def azure_create_sentinel_rule(workspace_name: str, rule_name: str, resource_group: str, query: str, severity: str = "Medium", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Sentinel analytics rule"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules/{rule_name}",
        "name": rule_name,
        "type": "Microsoft.SecurityInsights/alertRules",
        "properties": {
            "displayName": rule_name,
            "description": "Custom analytics rule",
            "severity": severity,
            "enabled": True,
            "query": query,
            "queryFrequency": "PT5M",
            "queryPeriod": "PT6H",
            "suppressionEnabled": False
        }
    }

@mcp.tool()
def azure_create_application_insights(app_name: str, resource_group: str, location: str = "East US", application_type: str = "web", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Application Insights"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Insights/components/{app_name}",
        "name": app_name,
        "type": "Microsoft.Insights/components",
        "location": location,
        "kind": application_type,
        "properties": {
            "Application_Type": application_type,
            "ApplicationId": app_name,
            "InstrumentationKey": "12345678-1234-1234-1234-123456789abc",
            "ConnectionString": f"InstrumentationKey=12345678-1234-1234-1234-123456789abc;IngestionEndpoint=https://{location}-0.in.applicationinsights.azure.com/",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_get_application_insights_metrics(app_name: str, resource_group: str, metric_name: str, timespan: str = "PT1H", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Get Application Insights metrics"""
    return {
        "value": {
            "start": "2024-01-01T11:00:00Z",
            "end": "2024-01-01T12:00:00Z",
            "interval": "PT5M",
            "segments": [
                {
                    "start": "2024-01-01T11:00:00Z",
                    "end": "2024-01-01T11:05:00Z",
                    f"{metric_name}": {
                        "sum": 150,
                        "avg": 25.5,
                        "count": 6
                    }
                }
            ]
        }
    }

@mcp.tool()
def azure_create_log_analytics_workspace(workspace_name: str, resource_group: str, location: str = "East US", sku: str = "pergb2018", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Log Analytics workspace"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}",
        "name": workspace_name,
        "type": "Microsoft.OperationalInsights/workspaces",
        "location": location,
        "properties": {
            "sku": {"name": sku},
            "retentionInDays": 30,
            "workspaceCapping": {"dailyQuotaGb": 1},
            "publicNetworkAccessForIngestion": "Enabled",
            "publicNetworkAccessForQuery": "Enabled",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_query_log_analytics(workspace_name: str, resource_group: str, query: str, timespan: str = "PT1H", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Query Azure Log Analytics workspace"""
    return {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Computer", "type": "string"},
                    {"name": "EventID", "type": "int"}
                ],
                "rows": [
                    ["2024-01-01T12:00:00Z", "VM1", 4624],
                    ["2024-01-01T12:01:00Z", "VM2", 4625]
                ]
            }
        ]
    }

@mcp.tool()
def azure_create_automation_account(account_name: str, resource_group: str, location: str = "East US", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Automation account"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Automation/automationAccounts/{account_name}",
        "name": account_name,
        "type": "Microsoft.Automation/automationAccounts",
        "location": location,
        "properties": {
            "sku": {"name": "Basic"},
            "state": "Ok",
            "registrationUrl": f"https://{location}-agentservice-prod-1.azure-automation.net/accounts/{account_name}",
            "provisioningState": "Creating"
        }
    }

@mcp.tool()
def azure_create_automation_runbook(account_name: str, runbook_name: str, resource_group: str, runbook_type: str = "PowerShell", api_token: Optional[str] = None) -> Dict[str, Any]:
    """Create Azure Automation runbook"""
    return {
        "id": f"/subscriptions/sub123/resourceGroups/{resource_group}/providers/Microsoft.Automation/automationAccounts/{account_name}/runbooks/{runbook_name}",
        "name": runbook_name,
        "type": "Microsoft.Automation/automationAccounts/runbooks",
        "properties": {
            "runbookType": runbook_type,
            "state": "New",
            "logVerbose": False,
            "logProgress": False,
            "creationTime": datetime.now().isoformat() + "Z",
            "lastModifiedTime": datetime.now().isoformat() + "Z"
        }
    }

app = mcp.sse_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9013)
