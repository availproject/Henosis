use ark_bn254::{Bn254, FqParameters, Fr, FrParameters, G1Projective, g1::Parameters, g1};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{Field, Fp256, Fp256Parameters, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{domain, Polynomial};
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use num_bigint::*;

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;

pub fn verify() {
    let alpha: Fp256<FrParameters> = Fr::from_str(
        "7322047676393218637481338970179134619960969643173747239601962635317485088344",
    )
    .unwrap();

    let beta: Fp256<FrParameters> = Fr::from_str(
        "555960103527329154567657609884853810354674391984649378679184507744444027027",
    )
    .unwrap();

    let gamma: Fp256<FrParameters> = Fr::from_str(
        "6957574725743056350363256008332060958376811930570348194340253625274403224161",
    )
    .unwrap();

    let xiseed: Fp256<FrParameters> = Fr::from_str(
        "7896530194749115621350184803828649182986933409800667201245111721654183640928",
    ).unwrap();

    let xiseed2: Fp256<FrParameters> = Fr::from_str(
        "9144946180881585340800612715529400610463547442756395931665142563665450056128",
    ).unwrap();

    let y: Fp256<FrParameters> = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    ).unwrap();

    let xi: Fp256<FrParameters> = Fr::from_str(
        "10393185035615259318552712605767090377249145892581385744729012713520677048218",
    ).unwrap();


    println!("Verifying proof...");

    let R0 = calculateR0(xi);
    let R1 = calculateR1(xi);
    calculateR2(xi, gamma, beta);
    // let R2 = calculateR2(xi);

}


fn calculateR0(xi: Fp256<FrParameters>)  -> Fp256<FrParameters> {
    let eval_ql = Fr::from_str("13012702442141574024514112866712813523553321876510290446303561347565844930654").unwrap();
    let eval_qr = Fr::from_str("6363613431504422665441435540021253583148414748729550612486380209002057984394").unwrap();
    let eval_qm = Fr::from_str("16057866832337652851142304414708366836077577338023656646690877057031251541947").unwrap();
    let eval_qo = Fr::from_str("12177497208173170035464583425607209406245985123797536695060336171641250404407").unwrap();
    let eval_qc = Fr::from_str("1606928575748882874942488864331180511279674792603033713048693169239812670017").unwrap();
    let eval_s1 = Fr::from_str("12502690277925689095499239281542937835831064619179570213662273016815222024218").unwrap();
    let eval_s2 = Fr::from_str("21714950310348017755786780913378098925832975432250486683702036755613488957178").unwrap();
    let eval_s3 = Fr::from_str("7373645520955771058170141217317033724805640797155623483741097103589211150628").unwrap();

    let y = Fr::from_str("13096643561003703188657823618924776735424142649986849213485512124502494958287").unwrap();

    let mut num = Fr::from_str("1").unwrap();
    let y__8 = y.pow([8]);
    num = num.mul(y__8);
    num = num.add(-xi);

    println!("num: {:?}", num.to_string());

    let mut h0w80 = Fr::from_str("6217280567245217757583020595539628144853576189258393757880925561134573660857").unwrap();

    let mut c0Value = eval_ql.add(h0w80.mul(eval_qr));
    println!("c0Value: {:?}", c0Value.to_string());

    let mut h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));
    
    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));
    
    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));
    
    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));
    
    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let pLiS0Inv_term = Fr::from_str("169426721603702040203361260122099036844252568090350847256434782251913759428").unwrap();
    let pH0w8_1_term = Fr::from_str("6467474964103268828445749503025875230771477005123038192746478572392917288085").unwrap();

    let res = c0Value.mul(num.mul(pLiS0Inv_term));

    println!("res: {:?}", res.to_string());

    h0w80 = pH0w8_1_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let pLiS0Inv_32_term = Fr::from_str("14857415132211068553935392518689134105014595040875579698823186778843823625742").unwrap();

    let res_2 = res.add(c0Value.mul(num.mul(pLiS0Inv_32_term)));

    println!("res_2: {:?}", res_2.to_string());

    let pH0w8_2_term = Fr::from_str("17058617445718799367294447696955508815020408034987705203621830040667799234184").unwrap();

    let pH0w8_3_term = Fr::from_str("21316856612335037613757111596833720133546507460560319301014759512314160286103").unwrap();
    let pH0w8_4_term = Fr::from_str("15670962304594057464663385149717646943694788211157640585817278625441234834760").unwrap();
    let pH0w8_5_term = Fr::from_str("15420767907736006393800656242231399857776887395292996150951725614182891207532").unwrap();
    let pH0w8_6_term = Fr::from_str("4829625426120475854951958048301766273527956365428329140076374145908009261433").unwrap();
    let pH0w8_7_term = Fr::from_str("571386259504237608489294148423554955001856939855715042683444674261648209514").unwrap();

    let pLiS0Inv_64_term = Fr::from_str("19499818470877388188618764011908347522427981376836110889591294651706164036883").unwrap();
    let pLiS0Inv_96_term  = Fr::from_str("12230430430123277051648593193909194010524731523942713458960326841142416752492").unwrap();
    let pLiS0Inv_128_term  = Fr::from_str("5126944045649383063127925823049128280433624872562175779448940177189724065181").unwrap();
    let pLiS0Inv_160_term  = Fr::from_str("5568669638657658207374981883763206083144030294353644128404077931588257238271").unwrap();
    let pLiS0Inv_192_term = Fr::from_str("13729581809580474302278683247897745531424316205584835263519833651663333148307").unwrap();
    let pLiS0Inv_224_term = Fr::from_str("10213683763403643593212850841764869657247040603744661309904686540295590892881").unwrap();


    h0w80 = pH0w8_2_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_3 = res_2.add(c0Value.mul(num.mul(pLiS0Inv_64_term)));
    println!("res_3: {:?}", res_3.to_string());

    h0w80 = pH0w8_3_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_4 = res_3.add(c0Value.mul(num.mul(pLiS0Inv_96_term)));
    println!("res_4: {:?}", res_4.to_string());

    h0w80 = pH0w8_4_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_5 = res_4.add(c0Value.mul(num.mul(pLiS0Inv_128_term)));
    println!("res_5: {:?}", res_5.to_string());

    h0w80 = pH0w8_5_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_6 = res_5.add(c0Value.mul(num.mul(pLiS0Inv_160_term)));
    println!("res_6: {:?}", res_6.to_string());

    h0w80 = pH0w8_6_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_7 = res_6.add(c0Value.mul(num.mul(pLiS0Inv_192_term)));
    println!("res_7: {:?}", res_7.to_string());

    h0w80 = pH0w8_7_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_8 = res_7.add(c0Value.mul(num.mul(pLiS0Inv_224_term)));
    println!("res_8: {:?}", res_8.to_string());

    res_8

}

fn calculateR1(xi: Fp256<FrParameters>) -> Fp256<FrParameters> {
    let mut num = Fr::from_str("1").unwrap();
    let y = Fr::from_str("13096643561003703188657823618924776735424142649986849213485512124502494958287").unwrap();
    let eval_a = Fr::from_str("10624974841759884514517518996672059640247361745924203600968035963539096078745").unwrap();
    let eval_b = Fr::from_str("12590031312322329503809710776715067780944838760473156014126576247831324341903").unwrap();
    let eval_c = Fr::from_str("17676078410435205056317710999346173532618821076911845052950090109177062725036").unwrap();
    let pi = Fr::from_str("8186154661026746046469382287670065360733981791589619791068274898784422808583").unwrap();
    let zinv = Fr::from_str("5003111610252004233397444097453114204704498339788572052799252538137556416518").unwrap();

    let H1w4_0 = Fr::from_str("19942750751199432676942609926442586439740980242021920220189719874523203538").unwrap();
    let H1w4_1 = Fr::from_str("6070134217614975914195815562203672780869780328825257598131939473058160967520").unwrap();
    let H1w4_2 = Fr::from_str("21868300121088075789569463135330832502108623420174012423478014466701285292079").unwrap();
    let H1w4_3 = Fr::from_str("15818108654224299308050590183053602307678584071590776745566264713517647528097").unwrap();
    let eval_ql = Fr::from_str("13012702442141574024514112866712813523553321876510290446303561347565844930654").unwrap();
    let eval_qr = Fr::from_str("6363613431504422665441435540021253583148414748729550612486380209002057984394").unwrap();
    let eval_qm = Fr::from_str("16057866832337652851142304414708366836077577338023656646690877057031251541947").unwrap();
    let eval_qo = Fr::from_str("12177497208173170035464583425607209406245985123797536695060336171641250404407").unwrap();
    let eval_qc = Fr::from_str("1606928575748882874942488864331180511279674792603033713048693169239812670017").unwrap();
    let pLiS1Inv_0_term = Fr::from_str("256600192143913399847065388940725172783235866632911365432425934771171503129").unwrap();
    let pLiS1Inv_32_term = Fr::from_str("3934696977981541056227007359974293215605002917158416054650075484355207678854").unwrap();
    let pLiS1Inv_64_term = Fr::from_str("10842349659271580751215767090163155520270237289395195387702921929214464444051").unwrap();
    let pLiS1Inv_96_term = Fr::from_str("14288814425393068574743899923526789505554250926531613540112244065507183041260").unwrap();


    let y__4 = y.pow([4]);
    num = num.mul(y__4);
    num = num.add(-xi);

    let mut t0 = eval_ql.mul(eval_a);
    println!("t0 1: {:?}", t0.to_string());
    t0 = t0.add(eval_qr.mul(eval_b));
    println!("t0 2: {:?}", t0.to_string());
    t0 = t0.add(eval_qm.mul(eval_a.mul(eval_b)));
    println!("t0 3: {:?}", t0.to_string());
    t0 = t0.add(eval_qo.mul(eval_c));
    println!("t0 4: {:?}", t0.to_string());
    t0 = t0.add(eval_qc);
    println!("t0 5: {:?}", t0.to_string());
    t0 = t0.add(pi);
    println!("t0 6: {:?}", t0.to_string());
    t0 = t0.mul(zinv);

    println!("t0: {:?}", t0.to_string());

    let mut c1Value = eval_a;
    c1Value = c1Value.add(H1w4_0.mul(eval_b));
    let mut square = H1w4_0.mul(H1w4_0);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_0)));

    let res_1 = c1Value.mul(num.mul(pLiS1Inv_0_term));
    println!("res_1: {:?}", res_1.to_string());

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_1.mul(eval_b));
    let mut square = H1w4_1.mul(H1w4_1);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_1)));

    let res_2 = res_1.add(c1Value.mul(num.mul(pLiS1Inv_32_term)));
    println!("res_2: {:?}", res_2.to_string());
    // pLiS1Inv_32_term

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_2.mul(eval_b));
    let mut square = H1w4_2.mul(H1w4_2);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_2)));

    let res_3 = res_2.add(c1Value.mul(num.mul(pLiS1Inv_64_term)));
    println!("res_3: {:?}", res_3.to_string());

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_3.mul(eval_b));
    let mut square = H1w4_3.mul(H1w4_3);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_3)));

    let res_4 = res_3.add(c1Value.mul(num.mul(pLiS1Inv_96_term)));
    println!("res_4: {:?}", res_4.to_string());

    res_4

}


fn calculateR2(xi: Fp256<FrParameters>, gamma: Fp256<FrParameters>, beta: Fp256<FrParameters>) {
    let eval_a = Fr::from_str("10624974841759884514517518996672059640247361745924203600968035963539096078745").unwrap();
    let eval_b = Fr::from_str("12590031312322329503809710776715067780944838760473156014126576247831324341903").unwrap();
    let eval_c = Fr::from_str("17676078410435205056317710999346173532618821076911845052950090109177062725036").unwrap();
    let w1 = Fr::from_str("5709868443893258075976348696661355716898495876243883251619397131511003808859").unwrap();
    let mut num = Fr::from_str("1").unwrap();
    let eval_z = Fr::from_str("13810130824095164415807955516712763121131180676617650812233616232528698737619").unwrap();
    let betaxi = Fr::from_str("15857722237427290894966863399309025470051084474506034024114905506714284882191").unwrap();
    let y = Fr::from_str("13096643561003703188657823618924776735424142649986849213485512124502494958287").unwrap();
    let y__6 = y.pow([6]);
    let k1 = Fr::from_str("2").unwrap();
    let k2 = Fr::from_str("3").unwrap();
    let eval_s1 = Fr::from_str("12502690277925689095499239281542937835831064619179570213662273016815222024218").unwrap();
    let eval_s2 = Fr::from_str("21714950310348017755786780913378098925832975432250486683702036755613488957178").unwrap();
    let eval_s3 = Fr::from_str("7373645520955771058170141217317033724805640797155623483741097103589211150628").unwrap();
    let eval_zw = Fr::from_str("9567903658565551430748252507556148460902008866092926659415720362326593620836").unwrap();
    let eval_l1 = Fr::from_str("17123728796310884659041981565369226818029855344213299425378416793319228696720").unwrap();
    let zinv = Fr::from_str("5003111610252004233397444097453114204704498339788572052799252538137556416518").unwrap();
    let h2w3_0 = Fr::from_str("1869756320377877312595498521504015597511420477452283464861296949200508189845").unwrap();
    let h2w3_1 = Fr::from_str("12855200334058046664672080384376966021199960394800133527288768963888158252355").unwrap();
    let h2w3_2 = Fr::from_str("7163286217403351244978826839376293469836983528163617351548138273487142053417").unwrap();
    let h3w3_0 = Fr::from_str("20221471501150487562916135566783003531433279751312695446481128041754069339168").unwrap();
    let h3w3_1 = Fr::from_str("5182315555253909512081724539694463779341668914354906154606878795853655230920").unwrap();
    let h3w3_2 = Fr::from_str("18372698687274153369494951384037082866321780135164467086308401535543892421146").unwrap();
    let pLiS2Inv_0_term = Fr::from_str("206374939483274985005531976845830683776047704156323693993869955347636075037").unwrap();
    let pLiS2Inv_32_term = Fr::from_str("17619227702648466802030149243931305700224905921105961026046579639394843879032").unwrap();
    let pLiS2Inv_64_term = Fr::from_str("7625875599226743107833355966417515764612634159114507249220768248349546906394").unwrap();
    let pLiS2Inv_96_term = Fr::from_str("21800233121663628999560820763114161007935197834912703103987736478449695374075").unwrap();
    let pLiS2Inv_128_term = Fr::from_str("10282071463295254039490411320866497845965519995172511751077123617826155505212").unwrap();
    let pLiS2Inv_160_term = Fr::from_str("13346764022296828137286564942239033331943591246683467841936936305120517223935").unwrap();
    let eval_t1w = Fr::from_str("17398514793767712415669438995039049448391479578008786242788501594157890722459").unwrap();
    let eval_t2w = Fr::from_str("11804645688707233673914574834599506530652461017683048951953032091830492459803").unwrap();

    num = num.mul(y__6);

    let mut num2 = Fr::one();
    num2 = num2.mul(y.pow([3]));

    num2 = num2.mul(xi.add(xi.mul(w1)));

    num = num.sub(num2);

    num2 = xi.mul(xi.mul(w1));
    num = num.add(num2);

    println!("num  1 : {:?}", num.to_string());
    println!("num2: {:?}", num2.to_string());

    let mut t2 = eval_a.add(betaxi.add(gamma));
    t2 =  t2.mul(eval_b.add(gamma.add(betaxi.mul(k1))));
    t2 = t2.mul(eval_c.add(gamma.add(betaxi.mul(k2))));
    t2 = t2.mul(eval_z);

    println!("t2: {:?}", t2.to_string());

    let mut t1 = eval_a.add(gamma.add(beta.mul(eval_s1)));
    t1 = t1.mul(eval_b.add(gamma.add(beta.mul(eval_s2))));
    t1 = t1.mul(eval_c.add(gamma.add(beta.mul(eval_s3))));
    t1 = t1.mul(eval_zw);

    println!("t1: {:?}", t1.to_string());

    t2 = t2.sub(t1);
    t2 = t2.mul(zinv);

    t1 = eval_z.sub(Fr::one());
    t1 = t1.mul(eval_l1);;
    t1 = t1.mul(zinv);

    println!("t1: {:?}", t1.to_string());    

    let mut gamma_r2 = Fr::zero();
    let mut hw = h2w3_0;
    let mut c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_0_term)));

    println!("gamma_r2 0 : {:?}", gamma_r2.to_string());

    hw = h2w3_1;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_32_term)));

    println!("gamma_r2 1 : {:?}", gamma_r2.to_string());

    hw = h2w3_2;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_64_term)));

    println!("gamma_r2 2 : {:?}", gamma_r2.to_string());

    hw = h3w3_0;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_96_term)));

    println!("gamma_r2 3 : {:?}", gamma_r2.to_string());

    hw = h3w3_1;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_128_term)));

    println!("gamma_r2 4 : {:?}", gamma_r2.to_string());

    hw = h3w3_2;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_160_term)));
    
    println!("gamma_r2 5: {:?}", gamma_r2.to_string());


    


    // num2 = 
    // num_r2_term
    // num2_r2_term
    // betaxi_term
    // gamma_term
    // t2_term
    // t1_r2
    // t1_xi_term
    // pH2w3_0_term
    // pLiS2Inv_0_term
    // pH2w3_1_term
    // pLiS2Inv_32_term
    // pH2w3_2_term
    // pLiS2Inv_64_term
    // pH3w3_0_term
    // pLiS2Inv_96_term
    // pH3w3_1_term
    // pLiS2Inv_128_term
    // pH3w3_2_term
    // pLiS2Inv_160_term






}