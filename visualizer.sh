#/usr/bin/env bash

volatility_path=volatility/
plugin_path=plugins/

cat messages/intro

if [[ $# -eq 0 ]] ; then
    echo "Usage : ./visualizer.sh <dumpfile> <profile>"
    echo "To find the profile you can use: ./visualizer.sh <dumpfile>"
elif [[ $# -eq 1 ]] ; then
    python $volatility_path/vol.py -f $1 imageinfo
    echo -e "\nPlease reuse this tool with one of the Suggested Profile(s) above as argument"
else
    filename="${1##*/}"

    cat messages/volatility
    #Using our memoryvisualizer plugin to access all the pages of memory and outputing the result in a file
    python $volatility_path/vol.py --plugins=$plugin_path -f $1 --profile=$2 memoryvisualizer > datas/output

    cat messages/image
    #Display the data from the file in an image format
    python imagegenerator.py $1 datas/output $filename
fi
