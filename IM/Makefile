# im:im.cpp im.hpp
# 	g++ -std=c++11 $^ -o $@ -L/usr/lib64/mysql -lpthread -lmysqlclient -ljsoncpp
# #-L/usr/lib64/mysql
# #指定mysql库文件的路径，这个路径不是默认路径，所以需要显式指定

im:im.cpp im.hpp mongoose.c
	g++ -std=c++11 $^ -o $@	-L/usr/lib64/mysql -lpthread -lmysqlclient -ljsoncpp
