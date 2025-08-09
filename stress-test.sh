#!/bin/bash

for i in {1..100}
do
  /Users/alikorsi/Documents/Typosentinel/bin/typosentinel scan dummy-package --local /Users/alikorsi/Documents/Typosentinel/large-package/package.json & > /dev/null 2>&1
done
