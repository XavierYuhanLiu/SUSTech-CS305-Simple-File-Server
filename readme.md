# CS305 Computer Network Project

主体部分是HttpServer，为每一个socket创建单独的进程，然后在每次回复完请求之后立即关闭


还没有写pipelining和persistent（orz 谁有空帮忙写一下

python3 server.py -i localhost -p 9000 启动程序
