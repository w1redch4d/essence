# Install llvm, lld, qemu and omvf.

# Create the drive with 'dd if=/dev/zero of=bin/uefi_drive bs=1024 count=262144'.
# Then using fdisk, make a GPT partition table with an EFI system partition and another partition of the default type.
# Enable the mkfs.fat command below for the first time you use the drive.
# Make sure that the build config has be set so that the primary drive size will fit in the partition.

# In Qemu, press Esc during startup to enter UEFI settings to change the boot order.
# In the EFI shell, type fs0: to navigate to the file system, and then type the name of the executable to run.

set -e

util/uefi_compile.sh

mkdir -p mount
LODEV=$(losetup -f)
sudo losetup --offset `fdisk -l bin/uefi_drive | grep 'EFI System' | awk '{print 512*$2}'` --sizelimit `fdisk -l bin/uefi_drive | grep 'EFI System' | awk '{print 512*$4}'` $LODEV bin/uefi_drive
sudo mkfs.fat $LODEV
sudo mount $LODEV mount
sudo mkdir -p mount/EFI/BOOT
sudo cp bin/uefi mount/EFI/BOOT/BOOTX64.EFI
sudo cp bin/uefi mount/es.efi
sudo cp ./root/Essence/Kernel.esx mount/eskernel.esx
sudo cp bin/uefi_loader mount/esloader.bin
sudo cp bin/iid.dat mount/esiid.dat
sudo umount $LODEV
sudo losetup --detach $LODEV
rmdir mount

dd if=bin/drive of=bin/uefi_drive bs=512 count=`fdisk -l bin/drive | grep 'Linux' | awk '{print $5}'` skip=`fdisk -l bin/drive | grep 'Linux' | awk '{print $3}'` seek=`fdisk -l bin/uefi_drive | grep 'Linux filesystem' | awk '{print $2}'` conv=notrunc

qemu-system-x86_64 -bios OVMF.fd -drive file=bin/uefi_drive,format=raw,media=disk,index=0 -s -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0,id=mykeyboard -device usb-mouse,bus=xhci.0,id=mymouse
