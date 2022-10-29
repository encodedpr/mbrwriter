
#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <commctrl.h>
#include <setupapi.h>
#include <cfg.h>
#include <assert.h>

#include "drive.h"
#include "dev.h"
#include "Header.h"
#define IGNORE_RETVAL(expr)         do { (void)(expr); } while(0)


VOID GetDevices()
{
	// List of USB storage drivers we know - list may be incomplete!
	const char* usbstor_name[] = {
		// Standard MS USB storage driver
		"USBSTOR",
		// USB card readers, with proprietary drivers (Realtek,etc...)
		// Mostly "guessed" from http://www.carrona.org/dvrref.php
		"RTSUER", "CMIUCR", "EUCR",
		// UASP Drivers *MUST* be listed after this, starting with "UASPSTOR"
		// (which is Microsoft's native UASP driver for Windows 8 and later)
		// as we use "UASPSTOR" as a delimiter
		"UASPSTOR", "VUSBSTOR", "ETRONSTOR", "ASUSSTPT"
	};
	// These are the generic (non USB) storage enumerators we also test
	const char* genstor_name[] = {
		// Generic storage drivers (Careful now!)
		"SCSI", // "STORAGE",	// "STORAGE" is used by 'Storage Spaces" and stuff => DANGEROUS!
		// Non-USB card reader drivers - This list *MUST* start with "SD" (delimiter)
		// See http://itdoc.hitachi.co.jp/manuals/3021/30213B5200e/DMDS0094.HTM
		// Also  http://www.carrona.org/dvrref.php. NB: All members from this list should have
		// been reported as enumerators by Rufus, when Enum Debug is enabled.
		"SD", "PCISTOR", "RTSOR", "JMCR", "JMCF", "RIMMPTSK", "RIMSPTSK", "RISD", "RIXDPTSK",
		"TI21SONY", "ESD7SK", "ESM7SK", "O2MD", "O2SD", "VIACR", "GLREADER"
	};
	// Oh, and we also have card devices (e.g. 'SCSI\DiskO2Micro_SD_...') under the SCSI enumerator...
	const char* scsi_disk_prefix = "SCSI\\Disk";
	const char* scsi_card_name[] = {
		"_SD_", "_SDHC_", "_MMC_", "_MS_", "_MSPro_", "_xDPicture_", "_O2Media_"
	};
	//const char* usb_speed_name[USB_SPEED_MAX] = { "USB", "USB 1.0", "USB 1.1", "USB 2.0", "USB 3.0", "USB 3.1" };
	const char* windows_sandbox_vhd_label = "PortableBaseLayer";
	// Hash table and String Array used to match a Device ID with the parent hub's Device Interface Path
	//htab_table htab_devid = HTAB_EMPTY;
	StrArray dev_if_path;
	char letter_name[] = " (?:)";
	char drive_name[] = "?:\\";
	char setting_name[32];
	char uefi_togo_check[] = "?:\\EFI\\Rufus\\ntfs_x64.efi";
	char scsi_card_name_copy[16];
	BOOL r = FALSE, found = FALSE, post_backslash;
	HDEVINFO dev_info = NULL;
	SP_DEVINFO_DATA dev_info_data;
	SP_DEVICE_INTERFACE_DATA devint_data;
	PSP_DEVICE_INTERFACE_DETAIL_DATA_A devint_detail_data;
	DEVINST parent_inst, grandparent_inst, device_inst;
	DWORD size, i, j, k, l, data_type, drive_index;
	DWORD uasp_start = ARRAYSIZE(usbstor_name), card_start = ARRAYSIZE(genstor_name);
	ULONG list_size[ARRAYSIZE(usbstor_name)] = { 0 }, list_start[ARRAYSIZE(usbstor_name)] = { 0 }, full_list_size, ulFlags;
	HANDLE hDrive;
	LONG maxwidth = 0;
	int s, u, v, score, drive_number, remove_drive, num_drives = 0;
	char drive_letters[27], * device_id, * devid_list = NULL, display_msg[128];
	char* p, * label, * display_name, buffer[MAX_PATH], str[MAX_PATH], device_instance_id[MAX_PATH], * method_str = NULL, * hub_path;

	usb_device_props props;


	ClearDrives();
	StrArrayCreate(&dev_if_path, 128);
	// Add a dummy for string index zero, as this is what non matching hashes will point to
	StrArrayAdd(&dev_if_path, "", TRUE);

	device_id = (char*)malloc(MAX_PATH);
	if (device_id == NULL)
		goto out;

	// Now use SetupDi to enumerate all our disk storage devices
	dev_info = SetupDiGetClassDevsA(&GUID_DEVINTERFACE_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (dev_info == INVALID_HANDLE_VALUE) {
		uprintf("SetupDiGetClassDevs (Interface) failed: %s", WindowsErrorString());
		goto out;
	}
	dev_info_data.cbSize = sizeof(dev_info_data);
	for (i = 0; num_drives < MAX_DRIVES && SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data); i++) {
		memset(buffer, 0, sizeof(buffer));
		memset(&props, 0, sizeof(props));
		//method_str = "";
		hub_path = NULL;
		if (!SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_ENUMERATOR_NAME,
			&data_type, (LPBYTE)buffer, sizeof(buffer), &size)) {
			uprintf("SetupDiGetDeviceRegistryProperty (Enumerator Name) failed: %s", WindowsErrorString());
			continue;
		}

		for (j = 0; j < ARRAYSIZE(usbstor_name); j++) {
			if (safe_stricmp(buffer, usbstor_name[0]) == 0) {
				props.is_USB = TRUE;
				if ((j != 0) && (j < uasp_start))
					props.is_CARD = TRUE;
				break;
			}
		}

		// UASP drives are listed under SCSI, and we also have non USB card readers to populate
		for (j = 0; j < ARRAYSIZE(genstor_name); j++) {
			if (safe_stricmp(buffer, genstor_name[j]) == 0) {
				props.is_SCSI = TRUE;
				if (j >= card_start)
					props.is_CARD = TRUE;
				break;
			}
		}

		uuprintf("Processing '%s' device:", buffer);
		if ((!props.is_USB) && (!props.is_SCSI)) {
			uuprintf("  Unsupported or disabled by policy");
			continue;
		}

		// We can't use the friendly name to find if a drive is a VHD, as friendly name string gets translated
		// according to your locale, so we poke the Hardware ID
		memset(buffer, 0, sizeof(buffer));
		props.is_VHD = SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_HARDWAREID,
			&data_type, (LPBYTE)buffer, sizeof(buffer), &size) && IsVHD(buffer);
		// Additional detection for SCSI card readers
		if ((!props.is_CARD) && (safe_strnicmp(buffer, scsi_disk_prefix, sizeof(scsi_disk_prefix) - 1) == 0)) {
			for (j = 0; j < ARRAYSIZE(scsi_card_name); j++) {
				static_strcpy(scsi_card_name_copy, scsi_card_name[j]);
				if (safe_strstr(buffer, scsi_card_name_copy) != NULL) {
					props.is_CARD = TRUE;
					break;
				}
				// Also test for "_SD&" instead of "_SD_" and so on to allow for devices like
				// "SCSI\DiskRicoh_Storage_SD&REV_3.0" to be detected.
				assert(strlen(scsi_card_name_copy) > 1);
				scsi_card_name_copy[strlen(scsi_card_name_copy) - 1] = '&';
				if (safe_strstr(buffer, scsi_card_name_copy) != NULL) {
					props.is_CARD = TRUE;
					break;
				}
			}
		}
		uuprintf("  Hardware ID: '%s'", buffer);

		// Keep track of the Device Instance ID, which we'll need to "reset" the device
		if (!SetupDiGetDeviceInstanceIdA(dev_info, &dev_info_data, device_instance_id,
			sizeof(device_instance_id), &size)) {
			uprintf("SetupDiGetDeviceInstanceId failed: %s", WindowsErrorString());
			strcpy(device_instance_id, "<N/A>");
		}

		memset(buffer, 0, sizeof(buffer));
		props.is_Removable = SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_info_data, SPDRP_REMOVAL_POLICY,
			&data_type, (LPBYTE)buffer, sizeof(buffer), &size) && IsRemovable(buffer);

		memset(buffer, 0, sizeof(buffer));
		if (!SetupDiGetDeviceRegistryPropertyU(dev_info, &dev_info_data, SPDRP_FRIENDLYNAME,
			&data_type, (LPBYTE)buffer, sizeof(buffer), &size)) {
			uprintf("SetupDiGetDeviceRegistryProperty (Friendly Name) failed: %s", WindowsErrorString());
			// We can afford a failure on this call - just replace the name with "USB Storage Device (Generic)"
			static_strcpy(buffer, lmprintf(MSG_045));
		}
		else if ((!props.is_VHD) && (devid_list != NULL)) {
			// Get the properties of the device. We could avoid doing this lookup every time by keeping
			// a lookup table, but there shouldn't be that many USB storage devices connected...
			// NB: Each of these Device IDs should have a child, from which we get the Device Instance match.
			for (device_id = devid_list; *device_id != 0; device_id += strlen(device_id) + 1) {
				if (CM_Locate_DevNodeA(&parent_inst, device_id, 0) != CR_SUCCESS) {
					uuprintf("Could not locate device node for '%s'", device_id);
					continue;
				}
				if (CM_Get_Child(&device_inst, parent_inst, 0) != CR_SUCCESS) {
					uuprintf("Could not get children of '%s'", device_id);
					continue;
				}
				if (device_inst != dev_info_data.DevInst) {
					// Try the siblings
					while (CM_Get_Sibling(&device_inst, device_inst, 0) == CR_SUCCESS) {
						if (device_inst == dev_info_data.DevInst) {
							uuprintf("NOTE: Matched instance from sibling for '%s'", device_id);
							break;
						}
					}
					if (device_inst != dev_info_data.DevInst)
						continue;
				}
				post_backslash = FALSE;
				method_str = "";

				// If we're not dealing with the USBSTOR part of our list, then this is an UASP device
				props.is_UASP = ((((uintptr_t)device_id) + 2) >= ((uintptr_t)devid_list) + list_start[uasp_start]);
				// Now get the properties of the device, and its Device ID, which we need to populate the properties
				ToUpper(device_id);
				j = htab_hash(device_id, &htab_devid);
				uuprintf("  Matched with ID[%03d]: %s", j, device_id);

				// Try to parse the current device_id string for VID:PID
				// We'll use that if we can't get anything better
				for (k = 0, l = 0; (k < strlen(device_id)) && (l < 2); k++) {
					// The ID is in the form USB_VENDOR_BUSID\VID_xxxx&PID_xxxx\...
					if (device_id[k] == '\\')
						post_backslash = TRUE;
					if (!post_backslash)
						continue;
					if (device_id[k] == '_') {
						props.pid = (uint16_t)strtoul(&device_id[k + 1], NULL, 16);
						if (l++ == 0)
							props.vid = props.pid;
					}
				}
				if (props.vid != 0)
					method_str = "[ID]";

				// If the hash didn't match a populated string in dev_if_path[] (htab_devid.table[j].data > 0),
				// we might have an extra vendor driver in between (e.g. "ASUS USB 3.0 Boost Storage Driver"
				// for UASP devices in ASUS "Turbo Mode" or "Apple Mobile Device USB Driver" for iPods)
				// so try to see if we can match the grandparent.
				if (((uintptr_t)htab_devid.table[j].data == 0)
					&& (CM_Get_Parent(&grandparent_inst, parent_inst, 0) == CR_SUCCESS)
					&& (CM_Get_Device_IDA(grandparent_inst, str, MAX_PATH, 0) == CR_SUCCESS)) {
					device_id = str;
					method_str = "[GP]";
					ToUpper(device_id);
					j = htab_hash(device_id, &htab_devid);
					uuprintf("  Matched with (GP) ID[%03d]: %s", j, device_id);
				}
				if ((uintptr_t)htab_devid.table[j].data > 0) {
					uuprintf("  Matched with Hub[%d]: '%s'", (uintptr_t)htab_devid.table[j].data,
						dev_if_path.String[(uintptr_t)htab_devid.table[j].data]);
					if (GetUSBProperties(dev_if_path.String[(uintptr_t)htab_devid.table[j].data], device_id, &props)) {
						method_str = "";
						hub_path = dev_if_path.String[(uintptr_t)htab_devid.table[j].data];
					}
#ifdef FORCED_DEVICE
					props.vid = FORCED_VID;
					props.pid = FORCED_PID;
					static_strcpy(buffer, FORCED_NAME);
#endif
				}
				break;
			}
		}
		if (props.is_VHD) {
			uprintf("Found VHD device '%s'", buffer);
		}
		else if ((props.is_CARD) && ((!props.is_USB) || ((props.vid == 0) && (props.pid == 0)))) {
			uprintf("Found card reader device '%s'", buffer);
		}
		else if ((!props.is_USB) && (!props.is_UASP) && (props.is_Removable)) {
			if (!list_non_usb_removable_drives) {
				uprintf("Found non-USB removable device '%s' => Eliminated", buffer);
				uuprintf("If you *REALLY* need, you can enable listing of this device with <Ctrl><Alt><F>");
				continue;
			}
			uprintf("Found non-USB removable device '%s'", buffer);
		}
		else {
			if ((props.vid == 0) && (props.pid == 0)) {
				if (!props.is_USB) {
					// If we have a non removable SCSI drive and couldn't get a VID:PID,
					// we are most likely dealing with a system drive => eliminate it!
					uuprintf("Found non-USB non-removable device '%s' => Eliminated", buffer);
					continue;
				}
				static_strcpy(str, "????:????");	// Couldn't figure VID:PID
			}
			else {
				static_sprintf(str, "%04X:%04X", props.vid, props.pid);
				// I *REALLY* don't want to erase the devices below by accident.
				if (its_a_me_mario) {
					if ((props.vid == 0x0525) && (props.pid == 0x622b))
						continue;
					if ((props.vid == 0x0781) && (props.pid == 0x75a0))
						continue;
					if ((props.vid == 0x10d6) && (props.pid == 0x1101))
						continue;
				}
				// Also ignore USB devices that have been specifically flagged by the user
				for (s = 0; s < ARRAYSIZE(ignore_vid_pid); s++) {
					if ((props.vid == (ignore_vid_pid[s] >> 16)) && (props.pid == (ignore_vid_pid[s] & 0xffff))) {
						uprintf("Ignoring '%s' (%s), per user settings", buffer, str);
						break;
					}
				}
				if (s < ARRAYSIZE(ignore_vid_pid))
					continue;
			}
			if (props.speed >= USB_SPEED_MAX)
				props.speed = 0;
			uprintf("Found %s%s%s device '%s' (%s) %s", props.is_UASP ? "UAS (" : "",
				usb_speed_name[props.speed], props.is_UASP ? ")" : "", buffer, str, method_str);
			if (props.lower_speed)
				uprintf("NOTE: This device is a USB 3.%c device operating at lower speed...", '0' + props.lower_speed - 1);
		}
		devint_data.cbSize = sizeof(devint_data);
		devint_detail_data = NULL;
		for (j = 0; ; j++) {
			safe_free(devint_detail_data);

			if (!SetupDiEnumDeviceInterfaces(dev_info, &dev_info_data, &GUID_DEVINTERFACE_DISK, j, &devint_data)) {
				if (GetLastError() != ERROR_NO_MORE_ITEMS) {
					uprintf("SetupDiEnumDeviceInterfaces failed: %s", WindowsErrorString());
				}
				else {
					uprintf("A device was eliminated because it didn't report itself as a disk");
				}
				break;
			}

			if (!SetupDiGetDeviceInterfaceDetailA(dev_info, &devint_data, NULL, 0, &size, NULL)) {
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
					devint_detail_data = (PSP_DEVICE_INTERFACE_DETAIL_DATA_A)calloc(1, size);
					if (devint_detail_data == NULL) {
						uprintf("Unable to allocate data for SP_DEVICE_INTERFACE_DETAIL_DATA");
						continue;
					}
					devint_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
				}
				else {
					uprintf("SetupDiGetDeviceInterfaceDetail (dummy) failed: %s", WindowsErrorString());
					continue;
				}
			}
			if (devint_detail_data == NULL) {
				uprintf("SetupDiGetDeviceInterfaceDetail (dummy) - no data was allocated");
				continue;
			}
			if (!SetupDiGetDeviceInterfaceDetailA(dev_info, &devint_data, devint_detail_data, size, &size, NULL)) {
				uprintf("SetupDiGetDeviceInterfaceDetail (actual) failed: %s", WindowsErrorString());
				continue;
			}

			hDrive = CreateFileA(devint_detail_data->DevicePath, GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hDrive == INVALID_HANDLE_VALUE) {
				uprintf("Could not open '%s': %s", devint_detail_data->DevicePath, WindowsErrorString());
				continue;
			}

			drive_number = GetDriveNumber(hDrive, devint_detail_data->DevicePath);
			CloseHandle(hDrive);
			if (drive_number < 0)
				continue;

			drive_index = drive_number + DRIVE_INDEX_MIN;
			if (!IsMediaPresent(drive_index)) {
				uprintf("Device eliminated because it appears to contain no media");
				safe_free(devint_detail_data);
				break;
			}
			if (GetDriveSize(drive_index) < (MIN_DRIVE_SIZE * MB)) {
				uprintf("Device eliminated because it is smaller than %d MB", MIN_DRIVE_SIZE);
				safe_free(devint_detail_data);
				break;
			}

			if (GetDriveLabel(drive_index, drive_letters, &label)) {
				if ((props.is_SCSI) && (!props.is_UASP) && (!props.is_VHD)) {
					if (!props.is_Removable) {
						// Non removables should have been eliminated above, but since we
						// are potentially dealing with system drives, better safe than sorry
						safe_free(devint_detail_data);
						break;
					}
					if (!list_non_usb_removable_drives) {
						// Go over the mounted partitions and find if GetDriveType() says they are
						// removable. If they are not removable, don't allow the drive to be listed
						for (p = drive_letters; *p; p++) {
							drive_name[0] = *p;
							if (GetDriveTypeA(drive_name) != DRIVE_REMOVABLE)
								break;
						}
						if (*p) {
							uprintf("Device eliminated because it contains a mounted partition that is set as non-removable");
							safe_free(devint_detail_data);
							break;
						}
					}
				}
				if ((!props.is_VHD) && (!props.is_CARD) &&
					((score = IsHDD(drive_index, (uint16_t)props.vid, (uint16_t)props.pid, buffer)) > 0)) {
					uprintf("Device eliminated because it was detected as a Hard Drive (score %d > 0)", score);
					if (!list_non_usb_removable_drives)
						uprintf("If this device is not a Hard Drive, please e-mail the author of this application");
					uprintf("NOTE: You can enable the listing of Hard Drives under 'advanced drive properties'");
					safe_free(devint_detail_data);
					break;
				}
				else if ((!enable_HDDs) && (props.is_CARD) && (GetDriveSize(drive_index) > MAX_DEFAULT_LIST_CARD_SIZE * GB)) {
					uprintf("Device eliminated because it was detected as a card larger than %d GB", MAX_DEFAULT_LIST_CARD_SIZE);
					uprintf("To use such a card, check 'List USB Hard Drives' under 'advanced drive properties'");
					safe_free(devint_detail_data);
					break;
				}
				// Windows 10 19H1 mounts a 'PortableBaseLayer' for its Windows Sandbox feature => unlist those
				if (safe_strcmp(label, windows_sandbox_vhd_label) == 0) {
					uprintf("Device eliminated because it is a Windows Sandbox VHD");
					safe_free(devint_detail_data);
					break;
				}
				if (props.is_VHD && (!enable_VHDs)) {
					uprintf("Device eliminated because listing of VHDs is disabled (Alt-G)");
					safe_free(devint_detail_data);
					break;
				}

				// The empty string is returned for drives that don't have any volumes assigned
				if (drive_letters[0] == 0) {
					display_name = lmprintf(MSG_046, label, drive_number,
						SizeToHumanReadable(GetDriveSize(drive_index), FALSE, use_fake_units));
				}
				else {
					// Find the UEFI:TOGO partition(s) (and eliminate them form our listing)
					for (k = 0; drive_letters[k]; k++) {
						uefi_togo_check[0] = drive_letters[k];
						if (PathFileExistsA(uefi_togo_check)) {
							for (l = k; drive_letters[l]; l++)
								drive_letters[l] = drive_letters[l + 1];
							k--;
						}
					}
					// We have multiple volumes assigned to the same device (multiple partitions)
					// If that is the case, use "Multiple Volumes" instead of the label
					static_strcpy(display_msg, (((drive_letters[0] != 0) && (drive_letters[1] != 0)) ?
						lmprintf(MSG_047) : label));
					for (k = 0, remove_drive = 0; drive_letters[k] && (!remove_drive); k++) {
						// Append all the drive letters we detected
						letter_name[2] = drive_letters[k];
						if (right_to_left_mode)
							static_strcat(display_msg, RIGHT_TO_LEFT_MARK);
						static_strcat(display_msg, letter_name);
						if (drive_letters[k] == (PathGetDriveNumberU(app_dir) + 'A'))
							remove_drive = 1;
						if (drive_letters[k] == (PathGetDriveNumberU(system_dir) + 'A'))
							remove_drive = 2;
					}
					// Make sure that we don't list any drive that should not be listed
					if (remove_drive) {
						uprintf("Removing %c: from the list: This is the %s!", toupper(drive_letters[--k]),
							(remove_drive == 1) ? "disk from which " APPLICATION_NAME " is running" : "system disk");
						safe_free(devint_detail_data);
						break;
					}
					safe_sprintf(&display_msg[strlen(display_msg)], sizeof(display_msg) - strlen(display_msg),
						"%s [%s]", (right_to_left_mode) ? RIGHT_TO_LEFT_MARK : "", SizeToHumanReadable(GetDriveSize(drive_index), FALSE, use_fake_units));
					display_name = display_msg;
				}

				rufus_drive[num_drives].index = drive_index;
				rufus_drive[num_drives].id = safe_strdup(device_instance_id);
				rufus_drive[num_drives].name = safe_strdup(buffer);
				rufus_drive[num_drives].display_name = safe_strdup(display_name);
				rufus_drive[num_drives].label = safe_strdup(label);
				rufus_drive[num_drives].size = GetDriveSize(drive_index);
				assert(rufus_drive[num_drives].size != 0);
				if (hub_path != NULL) {
					rufus_drive[num_drives].hub = safe_strdup(hub_path);
					rufus_drive[num_drives].port = props.port;
				}
				num_drives++;
				if (num_drives >= MAX_DRIVES)
					uprintf("Warning: Found more than %d drives - ignoring remaining ones...", MAX_DRIVES);
				safe_free(devint_detail_data);
				break;
			}
		}
	}
	SetupDiDestroyDeviceInfoList(dev_info);

out:
	// Set 'Start' as the selected button, so that tab selection works
	//SendMessage(hMainDialog, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hMainDialog, IDC_START), TRUE);
	safe_free(devid_list);
	StrArrayDestroy(&dev_if_path);
	//htab_destroy(&htab_devid);
	//return r;
}