# Windwos-EventLog-Bypass
Use subProcessTag Value From TEB to identify Event Log Threads.

Use NtQueryInformationThread API and I_QueryTagInformation API to get service name of the thread.

Auto kill Event Log Service Threads.

So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.

Learn from:

https://artofpwn.com/phant0m-killing-windows-event-log.html

and

https://github.com/hlldz/Invoke-Phant0m




