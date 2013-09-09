#!/bin/bash

eval "$(rbenv init -)"

PATH=`pwd`
MRUBY_PATH="/Users/Schmurfy/Dev/personal/mruby"

cd $MRUBY_PATH
MRUBY_CONFIG=$PATH/test_config.rb
pwd
rake
./bin/mruby $PATH/test.rb
