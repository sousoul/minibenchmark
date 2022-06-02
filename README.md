# minibenchmark
在main.go中，我们将区块链可信交易构件中涉及到的 Pedersen 承诺等密码学原语构建成一个benchmark，并在表4-1所示的 CPU 上进行了测试，用于测试密码学原语时间开销、存储开销测试。

在测试时，我们使用 runtime.GOMAXPROCS(1) 指令将基准程序占用的 CPU 设置为 1 核；同时将main.go中的变量orgNum设置成不同值，来改变系统中的组织数。

## 1.1 时间开销
### 1.1.1 代码使用
将main.go中的txN设为10（对密码学原语生成和验证的时间开销测试 10 次后取均值并记录）。将orgNum依次设置为2,4,6,8,10，编译并运行代码：

```bash
cd minibenchmark
go build // 编译
./awesomeProject2 // 运行
```

依次记录不同orgNum下代码运行完成后打印的时间开销。下图是txN=10，orgNum=10时，代码的一次时间开销测试结果示例。
<img width="424" alt="截屏2022-06-02 下午3 44 47" src="https://user-images.githubusercontent.com/49592082/171580146-83983d5a-d99a-4dd3-8637-a44c5c698831.png">

### 1.1.2 测试结果展示
表4-4、表4-5、图4-8展示了我们在一台MacBook pro上的测试的时间开销。

表4-4和表4-5分别展示了密码学原语生成的时间开销和零知识证明验证的时间开销，在这两部分时间开销中，范围证明和析取证明都占据了相 当大的一部分，且范围证明比析取证明耗时更长。

<img width="600" alt="截屏2022-06-02 下午3 39 36" src="https://user-images.githubusercontent.com/49592082/171579004-352d29ab-1464-491c-8322-4f7f25927d43.png">

<img width="600" alt="截屏2022-06-02 下午3 39 56" src="https://user-images.githubusercontent.com/49592082/171579062-fd436fce-9c5e-4c71-a7d5-53330485fffc.png">

图4-8将密码学原语生成和验证的总时间开销进行了对比。由图我们可得到两个结论，一是随着组织数增多，密码学原语生成和验证的总时间开销均随组织数成比例增长;二是相较于验证密码学原语的总时间开销，生成密码学原语所需的时间更多，约为验证所需时间的三倍。

<img width="600" alt="截屏2022-06-02 下午3 45 44" src="https://user-images.githubusercontent.com/49592082/171580314-e31884fb-157c-4891-915e-9eac4d62f6ff.png">

## 1.2 存储开销
### 2.1.1 代码使用
将main.go中的txN设为1（对密码学原语生成和验证的时间开销测试 10 次后取均值并记录）。将orgNum依次设置为2,4,6,8,10，编译并运行代码：

```bash
cd minibenchmark
go build // 编译
./awesomeProject2 // 运行
```

依次记录不同orgNum下代码运行完成后打印的存储开销。下图是txN=1，orgNum=10时，代码的一次存储开销测试结果示例。

<img width="551" alt="截屏2022-06-02 下午3 59 05" src="https://user-images.githubusercontent.com/49592082/171582835-952c6214-f410-4f00-b7d2-96d13fa88a6f.png">

### 2.1.2 测试结果展示
将orgNum依次设置为2,4,6,8,10，统计存储开销如图4-7所示。图4-7展示了系统中组织数和单笔转账记录存储开销的关系，可见单笔转账的存储开销和系统中的组织数成正比关系。注意：由于一次跨链资产兑换交易包含两次链内转账交易，因此整个跨链交易的存储开销约为图4-7中的两倍。

<img width="550" alt="截屏2022-06-02 下午3 51 29" src="https://user-images.githubusercontent.com/49592082/171581383-3fbd5f70-72bf-4116-bd6d-becea3c26fe2.png">


