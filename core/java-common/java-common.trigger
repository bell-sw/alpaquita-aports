#!/bin/sh

jvmpath=/usr/lib/jvm

find_tools() {
	find $jvmpath/default-jvm/jre/bin $jvmpath/default-jvm/bin \( -type f -o -type l \) -executable -exec readlink -f {} \; 2>/dev/null
}

install_symlinks() {
	# for Java 11+ jre/bin is a symlink to bin, but not for Java 8
	for exe in $(find_tools) ; do
		tool=$(basename $exe)
   		if [ -L /usr/bin/$tool ] ; then
               		prev=$(readlink -f /usr/bin/$tool)
               		[ "$exe" = "$prev" ] && continue
		fi
		ln -sf "$exe" -T /usr/bin/$tool
	done
}


uninstall_symlinks() {
	for exe in $(find_tools) ; do
        	tool=$(basename $exe)
        	[ -L /usr/bin/$tool ] && unlink /usr/bin/$tool
	done
}

clean_dangling_symlinks() {
	find /usr/bin -maxdepth 1 -type l | while read link ; do
		target=$(readlink "$link")
		case "$target" in
			"$jvmpath"*) [ -e "$target" ] || unlink "$link" ;;
		esac
	done
}


# delete all symlinks to the current java tools
uninstall_symlinks

# when we delete a package 'uninstall_symlinks' cannot delete old symlinks because at this moment the content
# of the package is already gone
clean_dangling_symlinks

cd $jvmpath
if [ -x $jvmpath/forced-jvm ]; then
	ln -sfn forced-jvm default-jvm
	install_symlinks
	exit 0
fi

# update default-jvm symlink (the newly installed jvm becomes latest)
latest=$(find $jvmpath -maxdepth 1 -type d -a -not -path $jvmpath -exec stat -c '%Y,%n' {} \; \
	| sort -rn | head -1 | cut -f2- -d,)
if [ "$latest" ]; then
	ln -sfn $latest default-jvm
	install_symlinks
fi

# remove default-jvm when all java deleted
[ -e $(readlink -f $jvmpath/default-jvm) ] || unlink $jvmpath/default-jvm

exit 0

