@echo off
title Fetch and pull github
color 7

git fetch 
git pull

timeout /t 5 /nobreak