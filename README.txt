# Against-Exchange-Pop3-Hacking

Read first,
You can adjust thresholds in the script, too strict values could cause wrong blocking impact normal use.
If you want remove some IP from block, you can remove the rule from windows firewall, or, add the ip address to FW_WhiteList.txt as |supper format temporaily, see FW_WhiteList.txt for more.
Deploy this script on every CAS serving internet

# How to use
1 This is a script to protect your AD passwords from hacking over Exchange Pop3
	if your exchange are attacking by someone over a internet published Pop3, probably this script can save u
2 Wrote by larry.song@outlook.com with powershell based on Windows 2012 R2 standard and Exchange 2013
3 Change your powershell execution policy to "RemoteSigned" via cmdlet "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned" - To allow the script run
4 Enable Pop3 logging for your CAS servers via "Set-PopSettings"
5 Enable Windows firewall - To block attacker's IP addresses
6 Set "Starter.cmd" invoked by task scheduler every 1 minute
7 Default Pop3 port in the script is 110, please change it if yours is different

- Larry.Song@outlook.com