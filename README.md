# DaoNodeSS

本項目fork自[onplus/shadowsocks-heroku](https://github.com/onplus/shadowsocks-heroku)
該項目原本是讓使用者在heroku上部屬shadowsocks，
所以在製作上是針對shadowsocks開發的，並不支援一般環境

本項目修改部分代碼，並且進行docker化
刻意選用空間量最小的Docker鏡像[mhart/alpine-node:4.9.1](https://hub.docker.com/r/mhart/alpine-node/)
盡可能的縮小容量，保證以最快的時間下載鏡像

# 用法
直接在workflow下載tar格式的鏡像，命名為ss.tar
```
docker load -i ss.tar
docker run -p 80:80 -e "KEY=<自訂的server密碼>" -d daonodess
```
