#!/bin/bash
# Script variables
DESTPATH="/ISO"
REPOFILE="40 9 31 288 321 10 4 6"
SINCEDATE=""
INCREMENTAL=0


change_date () {
    #Request new Since Date, verify it's a date
  local NEWDATE
  echo "Last successful .tar was created `cat ${DESTPATH}/Since 2>/dev/null || echo "Never"`"
  echo "ex: 2021-04-01T12:00:00Z"
  read -p "Enter Date (YYYY-MM-DDTMM:HH:SSZ): " NEWDATE
  echo "Incremental Start Date is now $NEWDATE. Is this correct?"
  select yn in Yes No; do
    case $yn in
        Yes) echo "$NEWDATE"; echo; break;;
        No) exit 4;;
    esac
  done
  SINCEDATE=$NEWDATE
}

space_check () {
    #Verify the number of repositories and the amount of space available is correct.
    #If Estimated space required is larger than what's available, exit with code 4.
    local space_avail=$(df -m ${DESTPATH} | awk '{ print $4 }' | tail -1 | cut -f 1)
    local multipli=${#REPOFILE[@]}
    printf "you are exporting %d Repositories to %s.  There is currently %dM space available at %s.\nsthis action will take up approximately %dM of space.\n\n" $multipli $DESTPATH $space_avail $DESTPATH $(( $multipli * 5000 ))
    select yn in Yes No; do
        case $yn in
            Yes) echo "Continuing...";
                if [[ $(( $multipli * 5000 >= $space_avail )) ]]; then
                    echo "NOT ENOUGH SPACE AT $DESTPATH TO SAFELY CONTINUE";
                fi
                exit 4;;


            No) break;;
        esac
    done

}

export_repos () {
# Export repositories
for i in ${REPOFILE}; do
  if [[ $incremental=1 ]]; then hammer repository export --organization-id 1 --id $i --since ${SINCEDATE};
  else hammer repository export --organization-id 1 --id $i; fi
  if [ $? != 0 ]; then echo $i >> /root/update_repos.txt; fi
done

# Copy the RPMs to the destination directory
for i in `find /var/lib/pulp/katello-export -type d -name "Packages" | cut -d \/ -f 1,2,3,4,5,6,7,8`; do
  pushd $i
  # Create destination directory
  if ! [ -d ${DESTPATH}/${SINCEDATE} ]; then mkdir -p ${DESTPATH}/${SINCEDATE}; fi
  rsync -Prtvc -L ./ ${DESTPATH}/${SINCEDATE}/Library/
  popd
done

# Delete the downloaded repositories from katello-export
pushd /var/lib/pulp/katello-export
rm -Rf *
popd

# Remove "listing" files from the destination directory
find ${DESTPATH}/${SINCEDATE} -name "listing" -exec rm -f {} +

# Remove any repodata files
for i in `find ${DESTPATH}/${SINCEDATE} -type d -name "repodata"`; do
  rm -f ${i}/*
done

# Pull the latest full repodata files
pushd /var/lib/pulp/published/yum/https/repos/Default_Organization/Library
for i in `find ${DESTPATH}/${SINCEDATE} -type d -name "repodata" | cut -d \/ -f 5,6,7,8,9,10,11,12,13,14`; do
  rsync -Prtvc -L --exclude "Packages/*" $i/ ${DESTPATH}/${SINCEDATE}/Library/$i/
done
popd

# Set file ownership
chown -R xadministrator:wheel ${DESTPATH}/${SINCEDATE}

# Create tarball
pushd ${DESTPATH}/${SINCEDATE}/Library
if [ -d ./custom ]; then mv custom content; fi
tar -cvf - ./ | split -db 500m - ${DESTPATH}/${SINCEDATE}.tar
cd ${DESTPATH}
sha256sum ${SINCEDATE}.tar >> sha256sum.txt
popd

#Timestamp file to record last tarball creation
if [[ ! -f ${DESTPATH}/Since ]]; then touch ${DESTPATH}/Since; fi
for y in "${DESTPATH}/Since"; do
    chattr -i $i
    echo `date -uIsecond` > $i
    chattr +i $i
done
}

help_response () {
printf "$0 [argument]\nExport repositories from Red Hat Satellite for purposes of importing to update disconnected Satellites.\n\n%10sincremental%-20sexport repositories since \$DATE.\n%10slast-export%-20sdisplay date of prior export.\n\n"
}

if [[ ${INCREMENTAL} = 0 ]]; then help_response; fi

case $1 in
    incremental)
        incremental=1
        change_date
        while [[ ! `date -d $SINCEDATE` ]]; do
            change_date
        done
        space_check
        export_repos
        ;;

    last-export)
        cat ${DESTPATH}/Since 2>/dev/null || echo "Never Exported"
        ;;
esac