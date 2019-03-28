#!/bin/bash
texcount -sum -inc -utf8 -sub=chapter $1

echo Number of words in $1 
    detex $1 | tr -cd '0-9A-Za-z $\tt\backslash$n' | wc -w
