#!/bin/bash
# echo aws s3 sync . s3://$1 --exclude \"s3_sync.sh\" --exclude \".git/*\" --exclude \".gitignore\" --exclude "\"local/*\""
aws s3 sync $1 s3://$2 --exclude ".git/*" --exclude ".gitignore" --exclude "local/*"