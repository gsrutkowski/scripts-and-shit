#!/bin/bash
# Script variables
DESTPATH="/ISO"
REPOFILE="40 9 31 288 321 10 4 6" 
SINCEDATE="2021-04-01T12:00:00Z"


# Export repositories
for i in ${REPOFILE}; do
  hammer repository export --organization-id 1 --id $i --since ${SINCEDATE}
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
#chown -R xadministrator:wheel ${DESTPATH}/${SINCEDATE}

# Create tarball
pushd ${DESTPATH}/${SINCEDATE}/Library
if [ -d ./custom ]; then mv custom content; fi
tar -cvf ${DESTPATH}/${SINCEDATE}.tar ./
cd ${DESTPATH}
sha256sum ${SINCEDATE}.tar >> sha256sum.txt
popd

