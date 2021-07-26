# 项目名称
网页IM即时通信
# 项目描述
实现通信系统,能够让用户通过浏览器进行注册,登录,进行多人聊天的系统
# 开发环境
Centos7.5-vim/g++/makefile/git
# 技术要求
HTTP协议,WebSocket协议,MySQL数据库,C++11,JSON数据格式
# 设计思路
基于MVC框架

数据管理模块:基于MySQL封装实现了用户信息状态管理功能

业务逻辑模块:基于mongoose库搭建HTTP服务器,实现登录注册聊天功能

前端页面模块:基于HTML+CSS+JS实现注册登录界面和聊天界面
