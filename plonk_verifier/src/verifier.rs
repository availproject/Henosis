use ark_ec::AffineCurve;

pub mod verifier {

    use ark_bn254::{Bn254, FqParameters, Fr, FrParameters, G1Projective, g1::Parameters, g1};
    use ark_ec::short_weierstrass_jacobian::GroupAffine;
    use ark_ec::*;
    use ark_ff::{Field, Fp256, One, PrimeField, UniformRand, Zero};
    use crate::utils::utils::get_vk;
    // use ark_ff::*;
    pub use crate::utils::utils::{get_plonk_proof, PlonkProof, KzgCommitment};
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

        // challenges
        let aplha: Fp256<FrParameters> = Fr::from_str(
            "20524487875464908209490178628685531130495322118498633336472062372490596458160",
        )
        .unwrap();
        let aplha2: Fp256<FrParameters> = Fr::from_str(
            "15078006696392234695360259740636700679685160725546870868598180534190235322590",
        )
        .unwrap();
        let beta: Fp256<FrParameters> = Fr::from_str(
            "1469297811652786173524431317518899500255817294137003269865683238937785575151",
        )
        .unwrap();
        let betaXi: Fp256<FrParameters> = Fr::from_str(
            "13225259735795124208355754745106974264820190639360930913938372355710361556434",
        )
        .unwrap();
        let gamma: Fp256<FrParameters> = Fr::from_str(
            "18662762454804078530469268494873062022326292981887766436251536958276002157418",
        )
        .unwrap();
        let u: Fp256<FrParameters> = Fr::from_str(
            "3671131478064498243238023262552279287106793140894919933179355516438710425648",
        )
        .unwrap();
        let v1: Fp256<FrParameters> = Fr::from_str(
            "14498287487861080416419858029046690078416135504177055334726844512695965479306",
        )
        .unwrap();
        let v2: Fp256<FrParameters> = Fr::from_str(
            "18486859084993980290861474858117854364521133753017300100785278076947352879482",
        )
        .unwrap();
        let v3: Fp256<FrParameters> = Fr::from_str(
            "14123602248794384244454650572711232922479511827410910736881997840343398040432",
        )
        .unwrap();
        let v4: Fp256<FrParameters> = Fr::from_str(
            "2148331607749528302422858560444633850556901391050132284183052763054829516667",
        )
        .unwrap();
        let v5: Fp256<FrParameters> = Fr::from_str(
            "4136526678804187529711616303688208869122242242984196786246124372892070082407",
        )
        .unwrap();
        let xi: Fp256<FrParameters> = Fr::from_str(
            "2036501310948870752400564319467871188178099508325597424996516092094167193038",
        ).unwrap();
        
        let u: Fp256<FrParameters> = Fr::from_str(
            "3671131478064498243238023262552279287106793140894919933179355516438710425648",
        )
        .unwrap();
        
        let xin: Fp256<FrParameters> = Fr::from_str(
            "18100393929293372189165175191067012844444248477558768048865905094957039702828",
        )
        .unwrap();
        let zh: Fp256<FrParameters> = Fr::from_str(
            "18100393929293372189165175191067012844444248477558768048865905094957039702827",
        )
        .unwrap();
    
        let n = Fr::from_str("2048").unwrap(); 

        let lagrange = calculateLagrange(n, xi);

        println!("Lagrange {:?}", lagrange);
        

        let proof: PlonkProof = get_plonk_proof();

        let pi = calculate_pi(lagrange, proof);

        let r0 = calcualteR0(aplha, aplha2, beta, gamma, proof, lagrange, pi);

        print!("final r0 {}", r0.to_string());


        //         let _pD:= add(pMem, pD)
        //         let gamma := mload(add(pMem, pGamma))
        //         let mIn := mload(0x40)
        //         mstore(0x40, add(mIn, 256)) // d1, d2, d3 & d4 (4*64 bytes)

        //         g1_setC(_pD, Qcx, Qcy)
        //         g1_mulAccC(_pD, Qmx, Qmy, mulmod(calldataload(pEval_a), calldataload(pEval_b), q))
        //         g1_mulAccC(_pD, Qlx, Qly, calldataload(pEval_a))
        //         g1_mulAccC(_pD, Qrx, Qry, calldataload(pEval_b))
        //         g1_mulAccC(_pD, Qox, Qoy, calldataload(pEval_c))            

        //         let betaxi := mload(add(pMem, pBetaXi))
        //         let val1 := addmod(
        //             addmod(calldataload(pEval_a), betaxi, q),
        //             gamma, q)

        //         let val2 := addmod(
        //             addmod(
        //                 calldataload(pEval_b),
        //                 mulmod(betaxi, k1, q),
        //                 q), gamma, q)

        //         let val3 := addmod(
        //             addmod(
        //                 calldataload(pEval_c),
        //                 mulmod(betaxi, k2, q),
        //                 q), gamma, q)

        //         let d2a := mulmod(
        //             mulmod(mulmod(val1, val2, q), val3, q),
        //             mload(add(pMem, pAlpha)),
        //             q
        //         )

        //         let d2b := mulmod(
        //             mload(add(pMem, pEval_l1)),
        //             mload(add(pMem, pAlpha2)),
        //             q
        //         )

        //         // We'll use mIn to save d2
        //         g1_calldataSet(add(mIn, 192), pZ)
        //         g1_mulSet(
        //             mIn,
        //             add(mIn, 192),
        //             addmod(addmod(d2a, d2b, q), mload(add(pMem, pU)), q))


        //         val1 := addmod(
        //             addmod(
        //                 calldataload(pEval_a),
        //                 mulmod(mload(add(pMem, pBeta)), calldataload(pEval_s1), q),
        //                 q), gamma, q)

        //         val2 := addmod(
        //             addmod(
        //                 calldataload(pEval_b),
        //                 mulmod(mload(add(pMem, pBeta)), calldataload(pEval_s2), q),
        //                 q), gamma, q)
    
        //         val3 := mulmod(
        //             mulmod(mload(add(pMem, pAlpha)), mload(add(pMem, pBeta)), q),
        //             calldataload(pEval_zw), q)
    

        //         // We'll use mIn + 64 to save d3
        //         g1_mulSetC(
        //             add(mIn, 64),
        //             S3x,
        //             S3y,
        //             mulmod(mulmod(val1, val2, q), val3, q))

        //         // We'll use mIn + 128 to save d4
        //         g1_calldataSet(add(mIn, 128), pT1)

        //         g1_mulAccC(add(mIn, 128), calldataload(pT2), calldataload(add(pT2, 32)), mload(add(pMem, pXin)))
        //         let xin2 := mulmod(mload(add(pMem, pXin)), mload(add(pMem, pXin)), q)
        //         g1_mulAccC(add(mIn, 128), calldataload(pT3), calldataload(add(pT3, 32)) , xin2)
                
        //         g1_mulSetC(add(mIn, 128), mload(add(mIn, 128)), mload(add(mIn, 160)), mload(add(pMem, pZh)))

        //         mstore(add(add(mIn, 64), 32), mod(sub(qf, mload(add(add(mIn, 64), 32))), qf))
        //         mstore(add(mIn, 160), mod(sub(qf, mload(add(mIn, 160))), qf))
        //         g1_acc(_pD, mIn)
        //         g1_acc(_pD, add(mIn, 64))
        //         g1_acc(_pD, add(mIn, 128))

        // calculateD()

        // print!("{:?}", proof);
        let d = calculateD(
            gamma, 
            betaXi, 
            Fp256::from(2), 
            lagrange, 
            aplha, 
            aplha2, 
            u ,
            beta,
            proof,
            xin,
            zh
        );    
      
        let f = calculate_f(proof, v1, v2, v3, v4, v5, d);
        println!("f x{:?}", f.x.to_string());
        println!("f y{:?}", f.y.to_string());

        println!("final r0 {}", r0.to_string());
        

        let e = calculate_E(r0, proof, u, v1, v2, v3, v4, v5);
        // print!("{:?}", proof);

        // let eval_l1 = Fp256::from_str("11988539173825008689538634671317926564558556971777001090206161159450797172546").unwrap();
                 
    
    }


   
    

    pub fn calculateD(
            gamma: Fp256<FrParameters>, 
            betaxi: Fp256<FrParameters>, 
            k2: Fp256<FrParameters>, 
            eval_l1: Fp256<FrParameters>, 
            alpha: Fp256<FrParameters>, 
            alpha2: Fp256<FrParameters>, 
            u: Fp256<FrParameters>,
            beta: Fp256<FrParameters>,
            proof: PlonkProof,
            xin: Fp256<FrParameters>,
            zh: Fp256<FrParameters>
        )-> GroupAffine<Parameters>
        
        {

            let qc_x = <G1Point as AffineCurve>::BaseField::from_str("0").unwrap();
            let qc_y = <G1Point as AffineCurve>::BaseField::from_str("0").unwrap();
            let qc_affine = G1Projective::new(qc_x, qc_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

            println!("qc_affine {:?}", qc_affine.to_string());

            

            let eval_a = proof.eval_a;
            let eval_b = proof.eval_b;
            let eval_c = proof.eval_c;
            let eval_a_into_eval_b = eval_a.mul(eval_b);
            
            let qm_x = <G1Point as AffineCurve>::BaseField::from_str("19151686162665193639218175163708172641368045642989460974532342422984533758298").unwrap();
            let qm_y = <G1Point as AffineCurve>::BaseField::from_str("16425900297592082064122235865674265321861003269908656946806802359646002523562").unwrap();
            let qm_affine = G1Projective::new(qm_x, qm_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

            let ql_x = <G1Point as AffineCurve>::BaseField::from_str("20835273517253247507278161354140085192179560558424391762960775729600393482750").unwrap();
            let ql_y = <G1Point as AffineCurve>::BaseField::from_str("16191201213275001001200617578554070333626688786050641588918630575263395623273").unwrap();
            let ql_affine = G1Projective::new(ql_x, ql_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

            let qr_x = <G1Point as AffineCurve>::BaseField::from_str("6900030744989144129848893583598672235257204177548311761347544245788955028280").unwrap();
            let qr_y = <G1Point as AffineCurve>::BaseField::from_str("8155125105494137927083991839474623324411895145542585614480259473774672439508").unwrap();
            let qr_affine = G1Projective::new(qr_x, qr_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

            let qo_x = <G1Point as AffineCurve>::BaseField::from_str("15946180093115511093353920492758773804069483402874922499479809500987551267911").unwrap();
            let qo_y = <G1Point as AffineCurve>::BaseField::from_str("10782711402358324053795706160377115050675566507577901529557399547946751276930").unwrap();
            let qo_affine = G1Projective::new(qo_x, qo_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();


        
            let mut d = qm_affine.mul(eval_a_into_eval_b).into_affine();

            println!("d {:?}", d.to_string());

            d = d.add(ql_affine.mul(eval_a).into_affine());

            println!("ql_a {:?}", d.to_string());

            d = d.add( qr_affine.mul(eval_b).into_affine());

            d = d.add(qo_affine.mul(eval_c).into_affine());

            println!("final d {:?}", d.to_string());

            //todo values should be in q field
            let mut val1 = (eval_a.add(betaxi)).add(gamma);
            println!("val1 {:?}", val1.to_string());

            let mut val2 = (eval_b.add(betaxi.mul(Fp256::from(2)))).add(gamma);
            println!("val2 {:?}", val2.to_string());

            let mut val3 = gamma.add(eval_c.add(betaxi.mul(Fp256::from(3))));
            println!("val3 {:?}", val3.to_string());

            let d2a = val1.mul(val2.mul(val3)).mul(alpha);

            let d2b = eval_l1.mul(alpha2);

            println!("d2a {:?}", d2a.to_string());
            println!("d2b {:?}", d2b.to_string());

            let proof = get_plonk_proof();

            let mut z = *proof.z.inner();

            //d2
            let d2 = z.mul(d2a.add(d2b).add(u)).into_affine();

            println!("d2 {:?}", d2.to_string());

            val1 = gamma.add(eval_a.add(proof.eval_s1.mul(beta)));

            println!("val1 {:?}", val1.to_string());

            val2 = gamma.add(eval_b.add(proof.eval_s2.mul(beta)));

            println!("val2 {:?}", val2.to_string());

            val3 = alpha.mul(beta).mul(proof.eval_zw);

            println!("val3 {:?}", val3.to_string());


            //d3

            let s3_x = <G1Point as AffineCurve>::BaseField::from_str("9950124792368664692570829131382246903633159137508810057227137955860009005660").unwrap();
            let s3_y = <G1Point as AffineCurve>::BaseField::from_str("14708106523280006289643854838096574099969523979927705115839740814287748610680").unwrap();
            let s3_affine = G1Projective::new(s3_x, s3_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

            let mut d3 = s3_affine.mul(val1.mul(val2.mul(val3))).into_affine();

            println!("d3 {:?}", d3.to_string());

            //d4

            let mut d4 = *proof.t1.inner();

            d4 = d4.add((*proof.t2.inner()).mul(xin).into_affine());

            let xin2 = xin.mul(xin);

            d4 = d4.add((*proof.t3.inner()).mul(xin2).into_affine());

            d4 = d4.mul(zh).into_affine();

            println!("d4 {:?}", d4.to_string());


            //final

            d3 = -d3;
            d4 = -d4;
            d = d.add(d2);
            d = d.add(d3);
            d = d.add(d4);

            println!("final d {:?}", d.to_string());

            d
}
    


    fn calculate_E(r0: Fp256<FrParameters>, proof: PlonkProof, u: Fp256<FrParameters>, v1: Fp256<FrParameters>, v2: Fp256<FrParameters>, v3: Fp256<FrParameters>, v4: Fp256<FrParameters>, v5: Fp256<FrParameters>) -> GroupAffine<Parameters> {
        let PlonkProof {
            eval_a: a,
            eval_b: b,
            eval_c: c,
            eval_s1: s1,
            eval_s2: s2,
            eval_zw: zw,
            ..
        } = proof;

        let mut s = -r0;
        s = s.add(a.mul(v1));
        s = s.add(b.mul(v2));
        s = s.add(c.mul(v3));
        s = s.add(s1.mul(v4));
        s = s.add(s2.mul(v5));
        s = s.add(zw.mul(u));

        let g1_x = <G1Point as AffineCurve>::BaseField::from_str("1").unwrap();
        let g1_y = <G1Point as AffineCurve>::BaseField::from_str("2").unwrap();
        
        let g1_affine = G1Projective::new(g1_x, g1_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

        let val = g1_affine.mul(s).into_affine();

        println!("val x {:?}", val.x.to_string());
        println!( "val y {:?}", val.y.to_string());

        val

        // println!("s {:?}", s.to_string());

    }

    fn calculate_pi(lagrange: Fp256<FrParameters>, proof: PlonkProof) -> Fp256<FrParameters> {
        let PlonkProof {
            pi: pub_input,
            ..
        } = proof;

        let pi_input = Fr::zero();

        let pi = pi_input.sub(lagrange.mul(pub_input));
        // println!("pi {:?}", pi.to_string());
        pi
    }

    pub fn calculate_f(proof: PlonkProof, v1: Fp256<FrParameters>, v2: Fp256<FrParameters>, v3: Fp256<FrParameters>, v4: Fp256<FrParameters>, v5: Fp256<FrParameters>, d: GroupAffine<Parameters>) -> GroupAffine<Parameters> {
        let PlonkProof {
            a: a,
            b: b,
            c: c,
            ..
        } = proof;

        let a_affine = a.0;
        let b_affine = b.0;
        let c_affine = c.0;

        let s_x_1 = <G1Point as AffineCurve>::BaseField::from_str("2277685636083563024253879452693986130212942936235758785876153581019640880319").unwrap();
        let s_y_1 = <G1Point as AffineCurve>::BaseField::from_str("5558146521438681597961812116362946523808729442181555954974750217085655765563").unwrap();
        
        let s1_affine = G1Projective::new(s_x_1, s_y_1, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

        let s_x_2 = <G1Point as AffineCurve>::BaseField::from_str("21421714290183048746230047877229262977674171892814788767166398067614207270732").unwrap();
        let s_y_2 = <G1Point as AffineCurve>::BaseField::from_str("18351947949312641279139525707675648861898823980801914700748293475468468405778").unwrap();
        
        let s2_affine = G1Projective::new(s_x_2, s_y_2, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        
        // let d_affine = G1Projective::new(d_x, d_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();


        let in_complete_f = a_affine.mul(v1).add(b_affine.mul(v2).add(c_affine.mul(v3).add(s1_affine.mul(v4).add(s2_affine.mul(v5))))).into_affine();        

        d.add(in_complete_f)

        // let f = (v1.mul(a)).add(v2.mul(b)).add(v3.mul(c)).add(v4.mul(s1)).add(v5.mul(s2)).add(zw);
        // f

    }

    pub fn calcualteR0(alpha: Fp256<FrParameters>, alpha2: Fp256<FrParameters>, beta: Fp256<FrParameters>, gamma: Fp256<FrParameters>, proof: PlonkProof, lagrange: Fp256<FrParameters>, pi: Fp256<FrParameters>) -> Fp256<FrParameters> {
        let PlonkProof {
            eval_a: a,
            eval_b: b,
            eval_c: c,
            eval_s1: s1,
            eval_s2: s2,
            eval_zw: zw,
            ..
        } = proof;

        let e1 = pi;
        println!("e1 {:?}", e1.to_string());
        // let e1b = BigInt::from_str(s1.to_string().as_str()).unwrap();
        let e2 = lagrange.mul(alpha2);
        println!("e2 {:?}", e2.to_string());
        
        let e3a = ((beta.mul(s1)).add(a)).add(gamma);

        println!("e3a {:?}", e3a.to_string());
        let e3b = (beta.mul(s2).add(b)).add(gamma);
        println!("e3b {:?}", e3b.to_string());
        let e3c = c.add(gamma);
        println!("e3c {:?}", e3c.to_string());
        let e3 = alpha.mul(zw.mul(e3c.mul(e3a.mul(e3b))));
        println!("e3 {:?}", e3.to_string());
        let ri  = e1.sub(e2);
        println!("ri {:?}", ri.to_string());
        let r0 = ri.sub(e3);

        r0
    }

    pub fn calculateLagrange(n: Fp256<FrParameters> , zh: Fp256<FrParameters>) -> Fp256<FrParameters> {
        let w = Fr::one();

        let denom = n * (zh - w);
        let domain: u64 = 2048;
        let numerator = w * (zh.pow([domain]) - w);
        let lagrange = numerator.mul(denom.inverse().unwrap());
        // let val = lagrange

        print!("Lagrange {:?}", lagrange.to_string());

        lagrange
    }
}