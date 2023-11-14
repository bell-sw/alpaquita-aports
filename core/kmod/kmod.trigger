#!/bin/sh

backup_vmlinuz="$(readlink /boot/vmlinuz.lts.bak)"

for i in "$@"; do
	[ -d "$i" ] || continue

	krel="${i#/lib/modules/}"

	# skip backup kernel
	[ "$backup_vmlinuz" ] && [ "vmlinuz-$krel" = "$backup_vmlinuz" ] && continue

	echo "Generate modules.* in $krel"
	/sbin/depmod $krel
done
