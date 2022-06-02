# minibenchmark
在main.go中，我们将区块链可信交易构件中涉及到的 Pedersen 承诺等密码学原语构建成一个benchmark，并在表4-1所示的 CPU 上进行了测试，用于测试密码学原语时间开销、存储开销测试。



### 1. 脚本使用

在测试时，我们使用 runtime.GOMAXPROCS(1) 指令将基准程序占用的 CPU 设置为 1 核；同时将main.go中的变量orgNum设置成不同值，来改变系统中的组织数。



#### 1.1 时间开销

将main.go中的txN设为10（对密码学原语生成和验证的时间开销测试 10 次后取均值并记录）。将orgNum依次设置为2,4,6,8,10，编译并运行代码：

```bash
cd minibenchmark
go build // 编译
./awesomeProject2 // 运行
```

依次记录不同orgNum下代码运行完成后打印的时间开销：



#### 1.2 存储开销

将main.go中的txN设为1（对密码学原语生成和验证的时间开销测试 10 次后取均值并记录）。将orgNum依次设置为2,4,6,8,10，编译并运行代码：

```bash
cd minibenchmark
go build // 编译
./awesomeProject2 // 运行
```

依次记录不同orgNum下代码运行完成后打印的存储开销：

