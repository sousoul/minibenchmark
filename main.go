package main

import (
	"awesomeProject2/protobuf"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/mit-dci/zksigma"

	"crypto/rand" // 随机数
	"github.com/golang/protobuf/proto"
)

// init函数和一般函数不一样，无法被调用（无论是包内还是包外）。init函数只在该文件被被引用时才执行（是import时，不是调用包函数时）。
//func init() {
//	s256 := sha256.New() // 看起来是计算哈希值的函数？？？
//
//	// This was changed in ZKSigma, but keys already generated part of the repo
//	// should still work. So reverted this to what was originally in ZKLedger,
//
//	// see:
//	// hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
//	// HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
//	curValue := btcec.S256().Gx // 正常的G的第一个分量
//	//fmt.Println(curValue)
//	s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which
//
//	potentialXValue := make([]byte, 33) // 似乎是生成一个33个字节的byte数组 [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
//	//fmt.Println(potentialXValue)
//	binary.LittleEndian.PutUint32(potentialXValue, 2) // [2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
//	//fmt.Println(potentialXValue)
//	//
//	for i, elem := range s256.Sum(nil) {
//		potentialXValue[i+1] = elem //[2 137 29 246 82 107 10 86 78 131 230 57 155 70 154 107 31 58 96 209 79 72 69 171 54 90 41 72 104 153 142 61 175]
//	}
//	//fmt.Println(potentialXValue)
//	H, err := btcec.ParsePubKey(potentialXValue, btcec.S256()) // ParsePubKey从字节串potentialXValue解析出一个koblitz曲线的公钥
//	fmt.Println(H)
//	if err != nil {
//		panic(err)
//	}
//	ZKLedgerCurve = zksigma.ZKPCurveParams{
//		C: btcec.S256(),
//		G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
//		H: zksigma.ECPoint{H.X, H.Y},
//	}
//	ZKLedgerCurve.HPoints = generateH2tothe()
//}

func ecpoint_json_marshal(p ECPoint) []byte {
	pJson, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err.Error())
	}
	return pJson
}
func bigint_json_marshal(bigInt *big.Int) []byte {
	bigIntJson, err := json.Marshal(bigInt)
	if err != nil {
		fmt.Println(err.Error())
	}
	return bigIntJson
}
func serialize_bulletproof(proof RangeProof, rangeProof *zkrow_package.RangeProof)  {
	// 1. ECpoint
	// Comm
	rangeProof.Comm = ecpoint_json_marshal(proof.Comm)

	// A
	rangeProof.A = ecpoint_json_marshal(proof.A)

	// S
	rangeProof.S = ecpoint_json_marshal(proof.S)

	// T1
	rangeProof.T1 = ecpoint_json_marshal(proof.T1)

	// T2
	rangeProof.T2 = ecpoint_json_marshal(proof.T2)

	// 2. bigint
	// Tau
	rangeProof.Tau = bigint_json_marshal(proof.Tau)

	// Th
	rangeProof.Th = bigint_json_marshal(proof.Th)

	// Mu
	rangeProof.Mu = bigint_json_marshal(proof.Mu)

	// Cy
	rangeProof.Cy = bigint_json_marshal(proof.Cy)

	// Cz
	rangeProof.Cz = bigint_json_marshal(proof.Cz)

	// Cx
	rangeProof.Cx = bigint_json_marshal(proof.Cx)

	// 3. IPP
	IPP_proto := &zkrow_package.InnerProdArg{}
	// L
	lJson, err := json.Marshal(proof.IPP.L)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.L = lJson
	// R
	rJson, err := json.Marshal(proof.IPP.R)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.R = rJson
	// A
	aBigintJson, err := json.Marshal(proof.IPP.A)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.A = aBigintJson
	// B
	bJson, err := json.Marshal(proof.IPP.B)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_proto.B = bJson
	// Challenges
	for i:=0; i<len(proof.IPP.Challenges); i++{
		challengeJson, err := json.Marshal(proof.IPP.Challenges[i])
		if err != nil {
			fmt.Println(err.Error())
		}
		IPP_proto.Challenges = append(IPP_proto.Challenges, challengeJson)
	}
	rangeProof.IPP = IPP_proto

}

func ecpoint_json_unmarshal(b []byte) ECPoint {
	p := &ECPoint{}
	err := json.Unmarshal(b, p)
	if err != nil {
		fmt.Println(err.Error())
	}
	return *p
}

func bigint_json_unmarshal(b []byte) *big.Int{
	bigint := &big.Int{}
	err := json.Unmarshal(b, bigint)
	if err != nil {
		fmt.Println(err.Error())
	}
	return bigint
}

func deserialize_bulletproof(rangeProof *zkrow_package.RangeProof, proof *RangeProof)  {
	// 1. ECpoint
	// Comm
	proof.Comm = ecpoint_json_unmarshal(rangeProof.Comm)

	// A
	proof.A = ecpoint_json_unmarshal(rangeProof.A)

	// S
	proof.S = ecpoint_json_unmarshal(rangeProof.S)

	// T1
	proof.T1 = ecpoint_json_unmarshal(rangeProof.T1)

	// T2
	proof.T2 = ecpoint_json_unmarshal(rangeProof.T2)

	// 2. bigint
	// Tau
	proof.Tau = bigint_json_unmarshal(rangeProof.Tau)

	// Th
	proof.Th = bigint_json_unmarshal(rangeProof.Th)

	// Mu
	proof.Mu = bigint_json_unmarshal(rangeProof.Mu)

	// Cy
	proof.Cy = bigint_json_unmarshal(rangeProof.Cy)

	// Cz
	proof.Cz = bigint_json_unmarshal(rangeProof.Cz)

	// Cx
	proof.Cx = bigint_json_unmarshal(rangeProof.Cx)

	// 3. IPP
	IPP_struct := InnerProdArg{}
	// L
	L := &[]ECPoint{}
	err := json.Unmarshal(rangeProof.IPP.L, L)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.L = *L
	// R
	R := &[]ECPoint{}
	err = json.Unmarshal(rangeProof.IPP.R, R)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.R = *R
	// A
	A := &big.Int{}
	err = json.Unmarshal(rangeProof.IPP.A, A)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.A = A
	// B
	B := &big.Int{}
	err = json.Unmarshal(rangeProof.IPP.B, B)
	if err != nil {
		fmt.Println(err.Error())
	}
	IPP_struct.B = B
	// Challenges
	for i:=0; i<len(rangeProof.IPP.Challenges); i++{
		tmp := &big.Int{}
		err = json.Unmarshal(rangeProof.IPP.Challenges[i], tmp)
		if err != nil {
			fmt.Println(err.Error())
		}
		IPP_struct.Challenges = append(IPP_struct.Challenges, tmp)
	}
	proof.IPP = IPP_struct
}

// comm = vG + rH
func Commitment(value *big.Int, r *big.Int) zksigma.ECPoint  {
	comm := zksigma.PedCommitR(ZKLedgerCurve, value, r)
	return comm
}

func test_commitment()  {
	value := big.NewInt(1)
	r := big.NewInt(0)

	//var c zksigma.ECPoint // 初始化为{<nil> <nil>}
	fmt.Println(ZKLedgerCurve.G, ZKLedgerCurve.H)

	c := Commitment(value, r)
	fmt.Println(c)
}

// token = rPk
func Token(pk zksigma.ECPoint, r *big.Int) zksigma.ECPoint {
	rtoken := zksigma.CommitR(ZKLedgerCurve, pk, r)
	return rtoken
}

// 比特币中的椭圆曲线为y3=x2+ax+b, a=0,b=7
func test_token()  {
	r := big.NewInt(2)
	//pk := ZKLedgerCurve.G
	pk := zksigma.ECPoint{big.NewInt(1), big.NewInt(1)} // 设置一个简单的奇点，以验证计算

	fmt.Println(pk)
	res := Token(pk, r)
	fmt.Println(res)
}


func Verify_bulletproof(rtn RangeProof) bool {
	r:=RPVerify(rtn)
	return r
}

func test_bulletproof()  {
	argCount := len(os.Args[1:])
	val:="255"

	if (argCount>0) { val = string(os.Args[1]) }
	if (argCount>1) { VecLength,_  = strconv.Atoi((os.Args[2])) }

	EC = NewECPrimeGroupKey(VecLength)
	m,_ := new(big.Int).SetString(val, 10) // 创建以10为基数的数字m
	fmt.Println("create range proof for value:", m)
	rtn, _:=RPProve(m)
	_ = rtn

}

//func init()  {
//	// 使用bulletproof中的椭圆曲线参数
//	ZKLedgerCurve = zksigma.ZKPCurveParams{
//		C: btcec.S256(), // 这个本身和bulletproof中是一样的
//		G: zksigma.ECPoint{EC.G.X, EC.G.Y},
//		H: zksigma.ECPoint{EC.H.X, EC.H.Y},
//	}
//	ZKLedgerCurve.HPoints = generateH2tothe() // HPoints不清楚有什么用，zkledger中也没有用到
//}

type TxSpecification struct {
	Pk []zksigma.ECPoint
	R []*big.Int // 计算token用到的随机数
	Value []*big.Int // 交易额
}

type orgPkSk struct {
	Pk []zksigma.ECPoint
	Sk []*big.Int
}

func GetR(zkpcp zksigma.ZKPCurveParams, value int64, orgNum int, spenderIdx int, receiverIdx int) TxSpecification {
	txSpe := TxSpecification{}
	totalR := big.NewInt(0)
	for i := 0; i < orgNum; i++ {
		// 1. 生成每个org承诺中的r
		if i!=orgNum-1{
			r, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
			if err != nil {
				fmt.Errorf("生成随机数错误")
			}
			txSpe.R = append(txSpe.R, r)
			totalR = totalR.Add(totalR, r)
		}else {
			r := new(big.Int).Sub(ZKLedgerCurve.C.Params().N, totalR)
			r.Mod(r, ZKLedgerCurve.C.Params().N)
			txSpe.R = append(txSpe.R, r)
		}
		if value < 0 {
			fmt.Errorf("value是一个正值，表示交易值")
		}
		// 2. 生成每个org的交易额
		if i==spenderIdx{
			txSpe.Value = append(txSpe.Value, big.NewInt(-value))
		} else if i==receiverIdx{
			txSpe.Value = append(txSpe.Value, big.NewInt(value))
		} else {
			txSpe.Value = append(txSpe.Value, big.NewInt(0))
		}
	}
	return txSpe
}

// 用于初始化二维账本
func GetRforInit(zkpcp zksigma.ZKPCurveParams, spenderIdx int, receiverIdx int, asset []int64) TxSpecification {
	txSpe := TxSpecification{}
	totalR := big.NewInt(0)
	//var asset = [2]int64 {100, 100} // 初始化数组长度只能用常量
	orgNum := len(asset)

	for i := 0; i < orgNum; i++ {
		// 1. 生成每个org承诺中的r
		if i!=orgNum-1{
			r, err := rand.Int(rand.Reader, zkpcp.C.Params().N)
			if err != nil {
				fmt.Errorf("生成随机数错误")
			}
			txSpe.R = append(txSpe.R, r)
			totalR = totalR.Add(totalR, r)
		}else {
			r := new(big.Int).Sub(ZKLedgerCurve.C.Params().N, totalR)
			r.Mod(r, ZKLedgerCurve.C.Params().N)
			txSpe.R = append(txSpe.R, r)
		}

		// 2. 初始化每个org的余额
		txSpe.Value = append(txSpe.Value, big.NewInt(asset[i]))
	}
	return txSpe
}

//func ProofofBalance(specification TxSpecification)  {
//	//commSum := zksigma.ECPoint{big.NewInt(0),big.NewInt(0)}
//	commSum := Commitment_myself(specification.Value[0], specification.R[0])
//	for i:=1; i<len(specification.Value);i++{
//		comm := Commitment_myself(specification.Value[i], specification.R[i])
//		commSum = ZKLedgerCurve.Add(commSum, comm)
//		fmt.Println(i, commSum)
//	}
//	fmt.Println(commSum)
//}


// 生成组织的公私钥
func Generate_sk_pk(orgNum int) orgPkSk {
	orgpksk := orgPkSk{}
	for i:=0; i<orgNum; i++{
		// 生成公私钥
		pk, sk := zksigma.KeyGen(ZKLedgerCurve.C, ZKLedgerCurve.H)
		orgpksk.Pk = append(orgpksk.Pk, pk)
		orgpksk.Sk = append(orgpksk.Sk, sk)
	}
	return orgpksk
}

func ECC_multi_scalar(pk zksigma.ECPoint, r *big.Int) zksigma.ECPoint {
	newR := new(big.Int).Mod(r, ZKLedgerCurve.C.Params().N)
	//X, Y := zkpcp.C.ScalarMult(pk.X, pk.Y, newR.Bytes()) // {commitR.X,commitR.Y} = newR * {pk.X, pk.Y}
	res := ZKLedgerCurve.Mult(pk, newR)
	return res
}

func Commitment_myself(value *big.Int, r *big.Int) zksigma.ECPoint{
	// modValue = value mod N
	modValue := new(big.Int).Mod(value, ZKLedgerCurve.C.Params().N)
	modRandom := new(big.Int).Mod(r, ZKLedgerCurve.C.Params().N)

	//X, Y := zkpcp.C.ScalarMult(pk.X, pk.Y, newR.Bytes()) // {commitR.X,commitR.Y} = newR * {pk.X, pk.Y}

	// mG, rH :: lhs, rhs
	//lhs := zkpcp.Mult(zkpcp.G, modValue)
	x, y := ZKLedgerCurve.C.ScalarMult(ZKLedgerCurve.G.X, ZKLedgerCurve.G.Y, modValue.Bytes())
	lhs := zksigma.ECPoint{x, y}
	x, y = ZKLedgerCurve.C.ScalarMult(ZKLedgerCurve.H.X, ZKLedgerCurve.H.Y, modRandom.Bytes())
	rhs := zksigma.ECPoint{x, y}

	//rhs := zkpcp.Mult(zkpcp.H, modRandom)

	//mG + rH
	return ZKLedgerCurve.Add(lhs, rhs)
}

func Create_bulletproof(m *big.Int) (RangeProof, *big.Int) {
	//m, _ := new(big.Int).SetString(val, 10) // 创建以10为基数的数字m
	RP_struct, r_RP := RPProve(m)
	return RP_struct, r_RP
}

// Token' = T.(Com_{RP}/S)^{sk}, for otherwise
func TokenPrime(T, Com_RP, S zksigma.ECPoint, sk *big.Int) zksigma.ECPoint {
	res1 := ZKLedgerCurve.Sub(Com_RP, S) // Com_{RP}/S
	res2 := zksigma.CommitR(ZKLedgerCurve, res1, sk) // (Com_{RP}/S)^{sk}
	res3 := ZKLedgerCurve.Add(T, res2) // T.(Com_{RP}/S)^{sk}
	return res3
}

// Token'' = Token.(Com_{RP}/S)^{sk}, for spending org
func TokenDoublePrime(Token, Com_RP, S zksigma.ECPoint, sk *big.Int) zksigma.ECPoint {
	res1 := ZKLedgerCurve.Sub(Com_RP, S) // Com_{RP}/S
	res2 := zksigma.CommitR(ZKLedgerCurve, res1, sk) // (Com_{RP}/S)^{sk}
	res3 := ZKLedgerCurve.Add(Token, res2) // Token.(Com_{RP}/S)^{sk}
	return res3
}

// 计算comm和token
func ZkPutState(value, r *big.Int, pk zksigma.ECPoint) (zksigma.ECPoint, zksigma.ECPoint) {
	comm := Commitment_myself(value, r)
	token := Token(pk, r)
	return comm, token
}

type AuditSpecification struct {
	Pk []zksigma.ECPoint // 所有组织公钥
	Sk *big.Int // 支出方私钥

	R []*big.Int //
	ValueforRangeProof []*big.Int // 支出方是余额，其他方是交易额

	SpenderIdx int
}

func CreateAuditSpecification(zkpcp zksigma.ZKPCurveParams, balance *big.Int, value int64, orgNum int, spenderIdx int, receiverIdx int) AuditSpecification {
	auditSpe := AuditSpecification{}
	if value < 0 {
		fmt.Errorf("value是一个正值，表示交易值")
	}
	// 生成每个org范围证明中的值
	for i:=0; i<orgNum; i++{
		if i==spenderIdx{
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, balance)
		} else if i==receiverIdx {
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, big.NewInt(value))
		} else {
			auditSpe.ValueforRangeProof = append(auditSpe.ValueforRangeProof, big.NewInt(0))
		}
	}
	return auditSpe
}

// 一行
type zkrow struct {
	Crypto []OrgColumn
	isValidBalCor bool
	isValidAsset bool
}

// OrgColumn represents one organization
type OrgColumn struct {
// transaction content
Comm zksigma.ECPoint
Token zksigma.ECPoint

// two step validation state
isValidBalCor bool
isValidAsset bool

// auxiliary data for proofs
TokenPrime zksigma.ECPoint
TokenDoublePrime zksigma.ECPoint

rp RangeProof
//dzkp *zksigma.DisjunctiveProof
dzkp Dzkp

S zksigma.ECPoint // 承诺之积
T zksigma.ECPoint // token之积
}

type Dzkp struct {
	proof *zksigma.DisjunctiveProof
	G1 zksigma.ECPoint
	Y1 zksigma.ECPoint
	G2 zksigma.ECPoint
	Y2 zksigma.ECPoint
}

var Ledger []*zkrow_package.Zkrow

func main() {
	fmt.Println("<------------------限制核心数----------------------->")
	runtime.GOMAXPROCS(1) //设置cpu的核的数量

	//fmt.Println("<------------------测试bulletproof中的耗时----------------------->")
	//test_bulletproof()

	fmt.Println("<------------------准备组织信息----------------------->")
	spenderIdx := 0
	receiverIdx := 1
	orgNum := 10
	var Asset []int64
	for i:=0;i<orgNum;i++{ // 初始余额
		Asset = append(Asset, 100)
	}

	orgPkSk := Generate_sk_pk(orgNum)

	value := int64(1)

	txSpeInit := GetRforInit(ZKLedgerCurve, 0, 1, Asset[:]) // 当前只有两个组织，Org0是支出方，Org1是接收方
	txSpeInit.Pk = orgPkSk.Pk
	fmt.Println("<------------------结束----------------------->")

	fmt.Println("<------------------计算密码学原语----------------------->")
	DuritionCalComm := int64(0) // 统计所有组织计算Comm的时间
	DuritionCalToken := int64(0) // 统计所有组织计算Token的时间
	DuritionCalRp := int64(0) // 统计所有组织计算Rp的时间
	DuritionCalDzkp := int64(0) // 统计所有组织计算Dzkp的时间

	DuritionVerBal := int64(0) // 统计所有组织验证Proof of Balance的时间
	DuritionVerCorr := int64(0) // 统计所有组织验证Proof of Correctness的时间
	DuritionVerRp := int64(0) // 统计所有组织验证Rp的时间
	DuritionVerDzkp := int64(0) // 统计所有组织验证Dzkp的时间

	//txN := 10 // 测试时间开销时，测试10次，取均值
	txN := 1 // 测试存储开销时，测试1次
	for txidx:=0;txidx<txN;txidx++{
		// txSpe
		txSpe := GetR(ZKLedgerCurve, value, orgNum, spenderIdx, receiverIdx)
		fmt.Println(txSpe.Value)
		txSpe.Pk = orgPkSk.Pk
		// auditSpe
		Asset[spenderIdx] = Asset[spenderIdx]-value // 支出方余额变化
		auditSpe := CreateAuditSpecification(ZKLedgerCurve, big.NewInt(Asset[spenderIdx]), value, orgNum, spenderIdx, receiverIdx) // 当前只有两个组织，Org0是支出方，Org1是接收方
		auditSpe.Pk = orgPkSk.Pk
		auditSpe.Sk = orgPkSk.Sk[spenderIdx] // 支出方的sk
		auditSpe.R = txSpe.R // 所有组织计算token用到的r
		auditSpe.SpenderIdx = spenderIdx

		// 定义账本中的一行，这里是以结构体指针的形式定义的
		zkrow := &zkrow_package.Zkrow {
			Columns: map[string]*zkrow_package.OrgColumn{},
			IsValidAsset: false,
			IsValidBalCor: false,
		}
		for i:=0; i<orgNum; i++{
			fmt.Println(fmt.Sprintf("=======组织%d生成证明=======", i+1))
			var tt1, tt2, tt3, tt4, tt5, tt6, tt7, tt8 int64 // 时间戳

			//fmt.Println("====计算承诺、Token====")
			tt1 = time.Now().UnixNano()/ 1e3 //
			comm := Commitment_myself(txSpe.Value[i], txSpe.R[i])

			tt2 = time.Now().UnixNano()/ 1e3 //
			tt3 = time.Now().UnixNano()/ 1e3 //
			token := Token(txSpe.Pk[i], txSpe.R[i])
			tt4 = time.Now().UnixNano()/ 1e3 //

			//fmt.Println("token", token)

			// 序列化
			commJsons, err := json.Marshal(comm) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}
			tokenJsons, err := json.Marshal(token) // []byte
			if err != nil {
				fmt.Println(err.Error())
			}

			// 定义一行中一个组织的信息
			org_info := &zkrow_package.OrgColumn{
				Commitment: commJsons,
				AuditToken: tokenJsons,
				IsValidBalCor: false,
				IsValidAsset: false,
			}
			org_name := "Org" + strconv.Itoa(i+1) // 定义一个组织名
			zkrow.Columns[org_name] = org_info // 将组织信息添加到账本中的一行

			//fmt.Println("====初始化账本余额====")
			s_last := zksigma.ECPoint{}
			t_last := zksigma.ECPoint{}
			if txidx==0{
				s_last = Commitment_myself(txSpeInit.Value[i], txSpeInit.R[i])
				t_last = Token(txSpeInit.Pk[i], txSpeInit.R[i])
			} else{
				s_last_json := Ledger[txidx-1].Columns[org_name].S
				err = json.Unmarshal(s_last_json, &s_last)
				t_last_json := Ledger[txidx-1].Columns[org_name].T
				err = json.Unmarshal(t_last_json, &t_last)
			}

			// 计算第j行的s, t
			s_new := ZKLedgerCurve.Add(s_last, comm)
			t_new := ZKLedgerCurve.Add(t_last, token)
			// 序列化并保存
			sJsons, err := json.Marshal(s_new)
			if err != nil {
				fmt.Println(err.Error())
			}
			tJsons, err := json.Marshal(t_new)
			if err != nil {
				fmt.Println(err.Error())
			}
			zkrow.Columns[org_name].S = sJsons
			zkrow.Columns[org_name].T = tJsons

			//crypt := OrgColumn{} // 当前组织的密码学原语
			if i==spenderIdx{
				// 计算支出方
				// 1. 创建范围证明
				//fmt.Println("====生成范围证明====")
				tt5 = time.Now().UnixNano()/ 1e3 //
				balance := auditSpe.ValueforRangeProof[i]
				fmt.Println("生成范围证明", balance)
				RP_struct, r_RP := Create_bulletproof(balance) // 生成余额的范围证明！
				tt6 = time.Now().UnixNano()/ 1e3 //

				// 这里有两种处理，a是用protobuf生成RP_proto，b是用JSON生成RP_btye
				// a. 将RP_struct序列化到RP_proto
				RP_proto := &zkrow_package.RangeProof{}
				serialize_bulletproof(RP_struct, RP_proto)

				// b. 测试能否直接将生成的范围证明序列为byte
				//RP_byte, err := json.Marshal(RP_struct)
				//if err != nil {
				//	fmt.Println(err.Error())
				//}

				// 2. 计算Token', Token''
				tt7 = time.Now().UnixNano()/ 1e3 //
				com_rp := zksigma.ECPoint{RP_struct.Comm.X, RP_struct.Comm.Y}  // 从范围证明中得到Com_{RP}
				tokenPrime := zksigma.CommitR(ZKLedgerCurve, auditSpe.Pk[i], r_RP)
				sk_spender, err := rand.Int(rand.Reader, ZKLedgerCurve.C.Params().N) // 支出方不能使用自己的私钥，用随机数代替
				if err != nil {
					panic(err)
				}
				tokenDoublePrime := TokenDoublePrime(token, com_rp, s_new, sk_spender)
				tokenPrimeJsons, err := json.Marshal(tokenPrime) // []byte
				if err != nil {
					fmt.Println(err.Error())
				}
				tokenDoublePrimeJsons, err := json.Marshal(tokenDoublePrime) // []byte
				if err != nil {
					fmt.Println(err.Error())
				}

				// 3. 创建DZKP
				//fmt.Println("====生成析取证明====")
				fmt.Println(s_new, t_new)
				G1 := ZKLedgerCurve.Sub(s_new, com_rp) // g1 = s/com_{RP}
				Y1 := ZKLedgerCurve.Sub(t_new, tokenPrime) // y1 = t/token'
				G2 := auditSpe.Pk[i] // g2 = pk，注意这里是支出方自己的公钥
				Y2 := ZKLedgerCurve.Sub(token, tokenDoublePrime) // g2 = token/token''
				x1 := auditSpe.Sk // x1 = sk
				proof, err := zksigma.NewDisjunctiveProof(ZKLedgerCurve, G1, Y1, G2, Y2, x1, 0) // 支出方要证g1^x1 = y1, x1=sk
				if err!=nil{
					fmt.Println(err)
				}
				tt8 = time.Now().UnixNano()/ 1e3 //

				// 序列化
				proofBytes := proof.Bytes() // 若g1^x1 ≠ y1，即x1是错误的值，则proof是空的，在这一步序列化时会报错
				G1Jsons, err := json.Marshal(G1)
				if err != nil {
					fmt.Println(err.Error())
				}
				Y1Jsons, err := json.Marshal(Y1)
				if err != nil {
					fmt.Println(err.Error())
				}
				G2Jsons, err := json.Marshal(G2)
				if err != nil {
					fmt.Println(err.Error())
				}
				Y2Jsons, err := json.Marshal(Y2)
				if err != nil {
					fmt.Println(err.Error())
				}

				// 4. 将Bulletproof, token', token'', DZKP保存到世界状态
				zkrow.Columns[org_name].TokenPrime = tokenPrimeJsons
				zkrow.Columns[org_name].TokenDoublePrime = tokenDoublePrimeJsons
				//zkrow.Columns[org_name].Rp = RP_byte
				zkrow.Columns[org_name].Rp = RP_proto
				dzkp := &zkrow_package.DisjunctiveProof{}
				dzkp.Proof = proofBytes
				dzkp.G1 = G1Jsons
				dzkp.Y1 = Y1Jsons
				dzkp.G2 = G2Jsons
				dzkp.Y2 = Y2Jsons
				zkrow.Columns[org_name].Dzkp = dzkp
			} else {
				// 计算其他方
				// 1. 创建范围证明
				//fmt.Println("====生成范围证明====")
				tt5 = time.Now().UnixNano()/ 1e3 //
				value := auditSpe.ValueforRangeProof[i]
				RP_struct, r_RP := Create_bulletproof(value) // 生成交易值的范围证明！
				tt6 = time.Now().UnixNano()/ 1e3 //

				// 这里有两种处理，a是用protobuf生成RP_proto，b是用JSON生成RP_btye
				// a. 将RP_struct序列化到RP_proto
				RP_proto := &zkrow_package.RangeProof{}
				serialize_bulletproof(RP_struct, RP_proto)

				// b. 测试能否直接将生成的范围证明序列为byte
				//RP_byte, err := json.Marshal(RP_struct)
				//if err != nil {
				//	fmt.Println(err.Error())
				//}

				// 2. 计算Token', Token''
				tt7 = time.Now().UnixNano()/ 1e3 //
				com_rp := zksigma.ECPoint{RP_struct.Comm.X, RP_struct.Comm.Y}  // 从范围证明中得到Com_{RP}
				sk_other, err := rand.Int(rand.Reader, ZKLedgerCurve.C.Params().N) // 支出方不知道其他方的私钥，用随机数代替
				if err != nil {
					panic(err)
				}
				tokenPrime := TokenPrime(t_new, com_rp, s_new, sk_other)
				tokenDoublePrime := zksigma.CommitR(ZKLedgerCurve, auditSpe.Pk[i], r_RP)
				tokenPrimeJsons, err := json.Marshal(tokenPrime) // []byte
				if err != nil {
					fmt.Println(err.Error())
				}
				tokenDoublePrimeJsons, err := json.Marshal(tokenDoublePrime) // []byte
				if err != nil {
					fmt.Println(err.Error())
				}

				// 3. 创建DZKP
				//fmt.Println("====生成析取证明====")
				G1 := ZKLedgerCurve.Sub(s_new, com_rp) // g1 = s/com_{RP}
				Y1 := ZKLedgerCurve.Sub(t_new, tokenPrime) // y1 = t/token'
				G2 := auditSpe.Pk[i] // g2 = pk，注意这里是各自的公钥
				Y2 := ZKLedgerCurve.Sub(token, tokenDoublePrime) // g2 = token/token''
				x2 := auditSpe.R[i].Sub(auditSpe.R[i], r_RP) // x2 = r-r_{RP}
				proof, err := zksigma.NewDisjunctiveProof(ZKLedgerCurve, G1, Y1, G2, Y2, x2, 1) // 其他方要证g2^x2 = y2, x2=r-r_{RP}
				tt8 = time.Now().UnixNano()/ 1e3 //

				// 序列化
				proofBytes := proof.Bytes() // 若g1^x1 ≠ y1，即x1是错误的值，则proof是空的，在这一步序列化时会报错
				G1Jsons, err := json.Marshal(G1)
				if err != nil {
					fmt.Println(err.Error())
				}
				Y1Jsons, err := json.Marshal(Y1)
				if err != nil {
					fmt.Println(err.Error())
				}
				G2Jsons, err := json.Marshal(G2)
				if err != nil {
					fmt.Println(err.Error())
				}
				Y2Jsons, err := json.Marshal(Y2)
				if err != nil {
					fmt.Println(err.Error())
				}

				// 4. 将Bulletproof, token', token'', DZKP保存到世界状态
				zkrow.Columns[org_name].TokenPrime = tokenPrimeJsons
				zkrow.Columns[org_name].TokenDoublePrime = tokenDoublePrimeJsons
				//zkrow.Columns[org_name].Rp = RP_byte
				zkrow.Columns[org_name].Rp = RP_proto
				dzkp := &zkrow_package.DisjunctiveProof{}
				dzkp.Proof = proofBytes
				dzkp.G1 = G1Jsons
				dzkp.Y1 = Y1Jsons
				dzkp.G2 = G2Jsons
				dzkp.Y2 = Y2Jsons
				zkrow.Columns[org_name].Dzkp = dzkp
			}

			DuritionCalComm += tt2-tt1
			DuritionCalToken += tt4-tt3
			DuritionCalRp += tt6-tt5
			DuritionCalDzkp += tt8-tt7
		}
		fmt.Println("<------------------结束----------------------->")

		Ledger = append(Ledger, zkrow) // 添加到账本
		fmt.Println("<------------------模拟账本序列化和反序列化----------------------->")
		// 序列化
		zkrowdata, err := proto.Marshal(zkrow) // protobuf序列化
		if err != nil {
			fmt.Println("Protobuf marshaling error")
		}

		fmt.Println(fmt.Sprintf("组织数：%d，共占%fKB\n", orgNum, float32(len(zkrowdata))/1024))
		time.Sleep(time.Hour)

		//反序列化
		//...
		fmt.Println("<------------------结束----------------------->")


		fmt.Println("<------------------验证NIZK----------------------->")
		for i:=0; i<orgNum; i++{
			org_name := "Org" + strconv.Itoa(i+1)
			var tt1, tt2, tt3, tt4, tt5, tt6, tt7, tt8 int64 // 时间戳
			fmt.Println(fmt.Sprintf("======组织%d验证======", i+1))
			// 1. Proof of Balance:
			tt1 = time.Now().UnixNano()/ 1e3 //
			commSum := zksigma.ECPoint{big.NewInt(0),big.NewInt(0)}
			for i:=0; i<orgNum; i++{
				org_name := "Org" + strconv.Itoa(i+1)
				commJson := zkrow.Columns[org_name].Commitment
				comm := zksigma.ECPoint{}
				err := json.Unmarshal(commJson, &comm)
				if err != nil {
					fmt.Println(err.Error())
				}
				commSum = ZKLedgerCurve.Add(commSum, comm) // 求和
				//fmt.Println(commSum)
			}
			res1 := commSum.Equal(zksigma.ECPoint{big.NewInt(0), big.NewInt(0)}) // bool
			fmt.Println("Proof of Balance:", res1)

			commJson := zkrow.Columns["Org1"].Commitment
			commSum2 := zksigma.ECPoint{}
			err = json.Unmarshal(commJson, &commSum2)
			//fmt.Println("承诺之和", commSum2)
			for i:=1; i<orgNum; i++{
				// 读取承诺
				org_name := "Org" + strconv.Itoa(i+1)
				commJson := zkrow.Columns[org_name].Commitment
				comm := zksigma.ECPoint{}
				err = json.Unmarshal(commJson, &comm)
				// 求和
				commSum2 = ZKLedgerCurve.Add(commSum2, comm)
				//fmt.Println("承诺之和", commSum2)
			}
			//fmt.Println("承诺之和", commSum2)
			res11 := commSum.Equal(zksigma.ECPoint{big.NewInt(0), big.NewInt(0)}) // bool
			fmt.Println(res11)
			//time.Sleep(time.Hour)

			tt2 = time.Now().UnixNano()/ 1e3 //
			zkrow.Columns[org_name].IsValidBalCor = res1

			// 2. Proof of Correctness:
			sk := orgPkSk.Sk[i]
			value := txSpe.Value[i]
			tokenJsons := zkrow.Columns[org_name].AuditToken
			token := zksigma.ECPoint{}
			err := json.Unmarshal(tokenJsons, &token)
			if err != nil {
				fmt.Println(err.Error())
			}
			commJson = zkrow.Columns[org_name].Commitment
			comm := zksigma.ECPoint{}
			err = json.Unmarshal(commJson, &comm)
			tt3 = time.Now().UnixNano()/ 1e3 //
			step1 := zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.G, sk) // g^{sk}
			step2 := zksigma.CommitR(ZKLedgerCurve, step1, value) // g^{sk.u}
			leftSide := ZKLedgerCurve.Add(token, step2) // token.g^{sk.u}
			rightSide := zksigma.CommitR(ZKLedgerCurve, comm, sk) // Com^{sk}
			res2 := leftSide.Equal(rightSide)
			fmt.Println("leftSide:", leftSide, "rightSide:", rightSide)
			fmt.Println("Proof of Correctness:", res2)
			tt4 = time.Now().UnixNano()/ 1e3 //

			// 3. 范围证明
			// a. JSON反序列化
			//RP_byte_ := zkrow.Columns[org_name].Rp
			//RP_struct_2 := &RangeProof{}
			//err = json.Unmarshal(RP_byte_, RP_struct_2)

			// b. protobuf反序列化
			RP_proto_ := zkrow.Columns[org_name].Rp
			RP_struct_2 := &RangeProof{}
			deserialize_bulletproof(RP_proto_, RP_struct_2)

			tt5 = time.Now().UnixNano()/ 1e3 //
			res3 := Verify_bulletproof(*RP_struct_2)
			fmt.Println("范围证明:", res3)
			tt6 = time.Now().UnixNano()/ 1e3 //
			zkrow.Columns[org_name].IsValidAsset = res3

			// 4. dzkp
			// 反序列化
			proofBytes := zkrow.Columns[org_name].Dzkp.Proof
			proof, err := zksigma.NewDisjunctiveProofFromBytes(proofBytes)
			if err!=nil{
				fmt.Println("dzkp反序列化报错")
			}
			G1 := zksigma.ECPoint{}
			json.Unmarshal(zkrow.Columns[org_name].Dzkp.G1, &G1)
			Y1 := zksigma.ECPoint{}
			json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y1, &Y1)
			G2 := zksigma.ECPoint{}
			json.Unmarshal(zkrow.Columns[org_name].Dzkp.G2, &G2)
			Y2 := zksigma.ECPoint{}
			json.Unmarshal(zkrow.Columns[org_name].Dzkp.Y2, &Y2)
			tokenDoublePrimeJsons := zkrow.Columns[org_name].TokenDoublePrime
			tokenDoublePrime := zksigma.ECPoint{}
			err = json.Unmarshal(tokenDoublePrimeJsons, &tokenDoublePrime)

			tt7 = time.Now().UnixNano()/ 1e3 //
			res4, _ := proof.Verify(ZKLedgerCurve, G1, Y1, G2, Y2)
			fmt.Println("验证DZKP", res4)
			// 补充证明
			//tokenDoublePrime := Ledger[0].Crypto[i].TokenDoublePrime
			if i!=spenderIdx{
				com_rp := zksigma.ECPoint{RP_struct_2.Comm.X, RP_struct_2.Comm.Y}  // 从范围证明中得到Com_{RP}
				leftSide = zksigma.CommitR(ZKLedgerCurve, ZKLedgerCurve.Sub(comm, com_rp), sk) //(Com/Com_{RP})^{sk_{other}}
				rightSide = ZKLedgerCurve.Sub(token, tokenDoublePrime) //Token/Token''
				res5 := leftSide.Equal(rightSide)
				fmt.Println("补充证明", res5)
			}
			tt8 = time.Now().UnixNano()/ 1e3 //

			DuritionVerBal += tt2-tt1
			DuritionVerCorr += tt4-tt3
			DuritionVerRp += tt6-tt5
			DuritionVerDzkp += tt8-tt7
		}

		zkrow.IsValidBalCor = true
		zkrow.IsValidAsset = true
		for i:=0; i<orgNum; i++{
			org_name := "Org" + strconv.Itoa(i+1) // 定义一个组织名
			if zkrow.Columns[org_name].IsValidBalCor == false{
				zkrow.IsValidBalCor = false
			}
			if zkrow.Columns[org_name].IsValidAsset == false{
				zkrow.IsValidAsset = false
			}
		}
		fmt.Println(fmt.Sprintf("一行的Proof of Balance：%v", zkrow.IsValidBalCor))
		fmt.Println(fmt.Sprintf("一行的Proof of Asset：%v", zkrow.IsValidAsset))

		fmt.Println("<------------------结束----------------------->")
	}

	fmt.Println(fmt.Sprintf("计算Comm：%vms\n" +
		"计算Token：%vms\n" +
		"计算Rp：%vms\n" +
		"计算Dzkp：%vms\n", float64(DuritionCalComm)/1e3/float64(txN), float64(DuritionCalToken)/1e3/float64(txN), float64(DuritionCalRp)/1e3/float64(txN), float64(DuritionCalDzkp)/1e3/float64(txN)))

	fmt.Println(fmt.Sprintf("验证Proof of Balance：%vms\n" +
		"验证Proof of Correctness：%vms\n" +
		"验证Rp：%vms\n" +
		"验证Dzkp：%vms\n", float64(DuritionVerBal)/1e3/float64(txN), float64(DuritionVerCorr)/1e3/float64(txN), float64(DuritionVerRp)/1e3/float64(txN), float64(DuritionVerDzkp)/1e3/float64(txN)))
}
