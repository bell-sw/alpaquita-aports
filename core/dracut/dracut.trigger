#!/bin/sh

backup="bak"

for i in /boot/vmlinuz.*; do
	[ -h "$i" ] || continue
	[ "${i##*.}" = "$backup" ] && continue

	kernel="$(readlink -f $i)"
	version="${kernel##*/vmlinuz-}"

	[ -d /lib/modules/"$version" ] || continue

	echo "Creating /boot/initramfs-$version"
	dracut --force -q /boot/initramfs-$version $version
done
