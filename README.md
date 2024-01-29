# Find ip
Use some online methods to find the real IP address behind the CDN
DNS resolution
Website analysis without www
Use the same icon, title, website certificate, etc.  

# 提示  
你可以在程序当中选择使用API进行查找，也可以选择不使用API进行。   
如果需要api需要配置在config.txt 其中包括censys，shodan的api。   
*censysy security_trail的API是免费的*   
具体实现可以看源代码配置。
## Background
In realworld pentest .We need to know the real ip address behind CDN protect so that we can do some exploit.This tool automatical do that thing!  

上面全是胡诌，真实情况是毕业需要一个毕设,所以瞎写了一个勉强能用的程序2333 

## Install
``` 
git clone https://github.com/Startr4ck/findip.git
python3 -r requirments.txt 
```

## Usage
python3 stats2.py 
or 
release stats2

## Show 
![image](https://github.com/Startr4ck/findip/blob/master/show.gif)   


## 还需要要做的  
* 打包程序 
* 优化速度 
