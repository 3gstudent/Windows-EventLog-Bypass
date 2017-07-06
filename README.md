# Windwos-EventLog-Bypass
Use subProcessTag Value From TEB to identify Event Log Threads.

Use NtQueryInformationThread API and I_QueryTagInformation API to get service name of the thread.

Auto kill Event Log Service Threads.

So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.

Learn from:

https://artofpwn.com/phant0m-killing-windows-event-log.html

and

https://github.com/hlldz/Invoke-Phant0m

Details about it:

https://3gstudent.github.io/3gstudent.github.io/%E5%88%A9%E7%94%A8API-NtQueryInformationThread%E5%92%8CI_QueryTagInformation%E5%AE%9E%E7%8E%B0%E5%AF%B9Windwos%E6%97%A5%E5%BF%97%E7%9B%91%E6%8E%A7%E7%9A%84%E7%BB%95%E8%BF%87/

