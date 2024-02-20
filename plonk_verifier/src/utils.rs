pub mod utils {

    use ark_bn254::{Bn254, Fr, G1Projective};
    use ark_poly::univariate::DensePolynomial;
    use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
    use ark_ff::{One};
    use std::{
        convert::TryInto, fmt::Display, ops::{Add, Mul}, rc::Rc, str::FromStr, sync::Mutex
    };

    pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
    pub type G2Point = <Bn254 as PairingEngine>::G2Affine;
    pub type Poly = DensePolynomial<Fr>;

    // pub struct KzgScheme<'a>(&'a Srs);
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KzgCommitment(pub G1Point);

    impl KzgCommitment {
        pub fn inner(&self) -> &G1Point {
            &self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PlonkProof {
        pub a: KzgCommitment,
        pub b: KzgCommitment,
        pub c: KzgCommitment,
        pub z: KzgCommitment,
        pub t1: KzgCommitment,
        pub t2: KzgCommitment,
        pub t3: KzgCommitment,
        pub eval_a: Fr,
        pub eval_b: Fr,
        pub eval_c: Fr,
        pub eval_s1: Fr,
        pub eval_s2: Fr,
        pub eval_zw: Fr,
        pub eval_r: Fr,
        pub pi: Fr,
        pub wxi: KzgCommitment,
        pub wxiw: KzgCommitment,
    }

    pub fn get_plonk_proof() -> PlonkProof {

        let a_x_p = <G1Point as AffineCurve>::BaseField::from_str("1078334906893789514326100165891809848019336850231558106434853250714105685786").unwrap();
        let a_y_p = <G1Point as AffineCurve>::BaseField::from_str("12948923423229301041562867238331904424847534881201052576626140469622636061826").unwrap();
        
        let a_affine = G1Projective::new(a_x_p, a_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        
        let a_commitment = KzgCommitment(a_affine);
        
        let b_x_p = <G1Point as AffineCurve>::BaseField::from_str("14871968772362298531943225503095829341924221467861921630107399429839476377261").unwrap();
        let b_y_p = <G1Point as AffineCurve>::BaseField::from_str("20832225230760737481879255829686244402434679017360094720847540179928583113429").unwrap();
        
        let b_affine: ark_ec::short_weierstrass_jacobian::GroupAffine<ark_bn254::g1::Parameters> = G1Projective::new(b_x_p, b_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let b_commitment = KzgCommitment(b_affine);
        
        let c_x_p = <G1Point as AffineCurve>::BaseField::from_str("11018249123771408599195936218586462295060894617169990047481063103297346617511").unwrap();
        let c_y_p = <G1Point as AffineCurve>::BaseField::from_str("20812079485764029398417948581030957233058448081114384385766482068306123340499").unwrap();
        
        let c_affine = G1Projective::new(c_x_p, c_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        
        let c_commitment = KzgCommitment(c_affine);
        
        let z_x_p = <G1Point as AffineCurve>::BaseField::from_str("18911369861849293400948671769181923953820381693244798480818014763242334194102").unwrap();
        let z_y_p = <G1Point as AffineCurve>::BaseField::from_str("17301903807617710475810560475296429124681646194334020082660695106153270924197").unwrap();
        
        let z_affine = G1Projective::new(z_x_p, z_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let z_commitment = KzgCommitment(z_affine);
        
        let wxi_x_p = <G1Point as AffineCurve>::BaseField::from_str("9035873252023575753720767347127457878893885607768879055873568678356030733580").unwrap();
        let wxi_y_p = <G1Point as AffineCurve>::BaseField::from_str("21585298432760990951017113608981855362693473929127174343206877901449604046764").unwrap();
        
        let wxi_affine = G1Projective::new(wxi_x_p, wxi_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let wxi_commitment = KzgCommitment(wxi_affine);
        
        let wxiw_x_p = <G1Point as AffineCurve>::BaseField::from_str("1849097023576595529567405124779246485506180099711177377631796309107793590717").unwrap();
        let wxiw_y_p = <G1Point as AffineCurve>::BaseField::from_str("10708519881826667651353678747174273508520559877623541936787968407888335454354").unwrap();
        
        let wxiw_affine = G1Projective::new(wxiw_x_p, wxiw_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let wxiw_commitment = KzgCommitment(wxiw_affine);
        
        let eval_zw = Fr::from_str("19038588322698518798348739810505212451458100152031223020479859202175121868652").unwrap();
        
        let t1_x_p = <G1Point as AffineCurve>::BaseField::from_str("8035481489412023854698082330728841837577166856942677235942161713802425228226").unwrap();
        let t1_y_p = <G1Point as AffineCurve>::BaseField::from_str("6100259826093601981346932339239322114347879658851780471127604889244409653156").unwrap();
        
        let t2_x_p = <G1Point as AffineCurve>::BaseField::from_str("10155064182436199621699595529626653722315634234955723925606936081123556290749").unwrap();
        let t2_y_p = <G1Point as AffineCurve>::BaseField::from_str("18176178013415694491760099032391438634755777914521625038595348247591920109678").unwrap();
        
        let t3_x_p = <G1Point as AffineCurve>::BaseField::from_str("17414543813591730681967718268670846901403831253033280305025278121489872982688").unwrap();
        let t3_y_p = <G1Point as AffineCurve>::BaseField::from_str("17180628559445942570926171368945985337988231638174686279031469310437333205328").unwrap();
        
        let t1_affine = G1Projective::new(t1_x_p, t1_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let t2_affine = G1Projective::new(t2_x_p, t2_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        let t3_affine = G1Projective::new(t3_x_p, t3_y_p, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();
        
        let t1_commitment = KzgCommitment(t1_affine);
        let t2_commitment = KzgCommitment(t2_affine);
        let t3_commitment = KzgCommitment(t3_affine);

        let proof: PlonkProof = PlonkProof {
            a: a_commitment,
            b: b_commitment,
            c: c_commitment,
            z: z_commitment,
            t1: t1_commitment,
            t2: t2_commitment,
            t3: t3_commitment,
            eval_a: Fr::from_str("7619444648548762352688989264071365525087666293572605752963973137331466620379").unwrap(),
            eval_b: Fr::from_str("12564993388515609407621530932388481577961227603586802807221481569176168238260").unwrap(),
            eval_c: Fr::from_str("6511986115001766925734365330664692166783761208764259458159980563836620574767").unwrap(),
            eval_s1: Fr::from_str("2812298524885313129731692194184506018747404376931025737870079617824503660557").unwrap(),
            eval_s2: Fr::from_str("18528016128263279091264827025576269655151738875625751164199105939098225113539").unwrap(),
            eval_zw: Fr::from_str("19038588322698518798348739810505212451458100152031223020479859202175121868652").unwrap(),
            eval_r: Fr::from_str("11410710969449562470071038294456377378562621755076252052836692477638805717495").unwrap(),
            pi: Fr::from_str("7713112592372404476342535432037683616424591277138491596200192981572885523208").unwrap(),
            wxi: wxi_commitment,
            wxiw: wxiw_commitment,
        };
        proof
    }

    pub fn get_vk() {
        
    }
}