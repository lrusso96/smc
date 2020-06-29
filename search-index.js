var searchIndex = JSON.parse('{\
"smc":{"doc":"`smc`","i":[[0,"commitment","smc","A simple commitment scheme implementation.",null,null],[0,"elgamal","smc::commitment","",null,null],[3,"Committer","smc::commitment::elgamal","El-Gamal Committer is represented here",null,null],[3,"Commit","","",null,null],[3,"Opening","","",null,null],[0,"ec","","",null,null],[6,"Committer","smc::commitment::elgamal::ec","",null,null],[6,"Commit","","",null,null],[11,"new","smc::commitment::elgamal","Generates a new instance of El-Gamal Committer.",0,[[],[["result",4],["errorstack",3],["committer",6]]]],[11,"new","smc::commitment::elgamal::ec","Generates a new instance of El-Gamal Committer.",1,[[],[["result",4],["errorstack",3],["committer",6]]]],[0,"mult","smc::commitment::elgamal","",null,null],[6,"Committer","smc::commitment::elgamal::mult","",null,null],[6,"Commit","","",null,null],[11,"new","smc::commitment::elgamal","Generates a new instance of El-Gamal Committer.",0,[[],[["errorstack",3],["result",4],["committer",6]]]],[11,"new","smc::commitment::elgamal::mult","Generates a new instance of El-Gamal Committer.",2,[[],[["errorstack",3],["result",4],["committer",6]]]],[6,"CommitterMult","smc::commitment::elgamal","",null,null],[6,"CommitMult","","",null,null],[6,"CommitterEc","","",null,null],[6,"CommitEc","","",null,null],[0,"pedersen","smc::commitment","",null,null],[3,"Committer","smc::commitment::pedersen","A Pedersen Committer is represented here.",null,null],[3,"Opening","","",null,null],[0,"ec","","",null,null],[6,"Committer","smc::commitment::pedersen::ec","",null,null],[6,"Commit","","",null,null],[11,"new","smc::commitment::pedersen","Generates a new instance of Pedersen Committer.",3,[[],[["errorstack",3],["result",4],["committer",6]]]],[11,"new","smc::commitment::pedersen::ec","Generates a new instance of Pedersen Committer.",4,[[],[["errorstack",3],["result",4],["committer",6]]]],[0,"mult","smc::commitment::pedersen","",null,null],[6,"Committer","smc::commitment::pedersen::mult","",null,null],[6,"Commit","","",null,null],[11,"new","smc::commitment::pedersen","Generates a new instance of Pedersen Committer.",3,[[],[["result",4],["errorstack",3],["committer",6]]]],[11,"new","smc::commitment::pedersen::mult","Generates a new instance of Pedersen Committer.",5,[[],[["result",4],["errorstack",3],["committer",6]]]],[6,"CommitterMult","smc::commitment::pedersen","",null,null],[6,"CommitterEc","","",null,null],[6,"CommitMult","","",null,null],[6,"CommitEc","","",null,null],[6,"Commit","","",null,null],[6,"ElGamalCommitMult","smc::commitment","",null,null],[6,"ElGamalCommitterMult","","",null,null],[6,"ElGamalCommitEc","","",null,null],[6,"ElGamalCommitterEc","","",null,null],[6,"PedersenCommitMult","","",null,null],[6,"PedersenCommitterMult","","",null,null],[6,"PedersenCommitEc","","",null,null],[6,"PedersenCommitterEc","","",null,null],[8,"Message","","",null,null],[8,"Commit","","",null,null],[8,"Opening","","",null,null],[8,"Committer","","The main trait Committer offers the possibility to commit…",null,null],[10,"commit","","",6,[[["bignum",3]],[["errorstack",3],["result",4]]]],[10,"verify","","",6,[[],[["result",4],["errorstack",3]]]],[0,"group","smc","A simple wrapper for groups where Discrete Log problem is…",null,null],[3,"EllipticCurveGroup","smc::group","A simple wrapper of EcGroup.",null,null],[3,"MultiplicativeGroup","","Represents the multiplicative group Zp*, where p is a safe…",null,null],[11,"new","","Creates a new EllipticCurveGroup.",7,[[["nid",3]],[["errorstack",3],["result",4]]]],[11,"new","","",8,[[],[["errorstack",3],["result",4]]]],[8,"DLogGroup","","This is the trait for groups where Discrete Log (DL)…",null,null],[10,"get_generator","","Retrieves the generator `g` for the group.",9,[[]]],[10,"get_order","","Returns the order of the group.",9,[[],["bignum",3]]],[10,"generate_random_element","","Generates a random element in the group.",9,[[]]],[10,"generate_random_exponent","","Generates a random exponent",9,[[],["bignum",3]]],[10,"exponentiate","","Computes an exponentiation between two elements in the…",9,[[["bignum",3]]]],[10,"multiply","","Computes the multiplication between two elements in the…",9,[[]]],[10,"pow","","Computes the pow.",9,[[["bignum",3]]]],[10,"eq","","Compares two elements in a group.",9,[[]]],[8,"Element","","This trait represents an element of a group.",null,null],[0,"utils","smc","Utilities for secure random number generation. This is a…",null,null],[5,"rand_range","smc::utils","Generates a random `BigNum` between 1 and `limit` - 1.",null,[[["bignum",3]],[["result",4],["errorstack",3],["bignum",3]]]],[5,"rand","","Generates a random `BigNum` with `secpar` bits.",null,[[],[["result",4],["errorstack",3],["bignum",3]]]],[11,"from","smc::commitment::elgamal","",0,[[]]],[11,"into","","",0,[[]]],[11,"borrow","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"borrow_mut","","",0,[[]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"from","","",10,[[]]],[11,"into","","",10,[[]]],[11,"borrow","","",10,[[]]],[11,"try_from","","",10,[[],["result",4]]],[11,"try_into","","",10,[[],["result",4]]],[11,"borrow_mut","","",10,[[]]],[11,"type_id","","",10,[[],["typeid",3]]],[11,"from","","",11,[[]]],[11,"into","","",11,[[]]],[11,"borrow","","",11,[[]]],[11,"try_from","","",11,[[],["result",4]]],[11,"try_into","","",11,[[],["result",4]]],[11,"borrow_mut","","",11,[[]]],[11,"type_id","","",11,[[],["typeid",3]]],[11,"from","smc::commitment::pedersen","",3,[[]]],[11,"into","","",3,[[]]],[11,"borrow","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"borrow_mut","","",3,[[]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"from","","",12,[[]]],[11,"into","","",12,[[]]],[11,"borrow","","",12,[[]]],[11,"try_from","","",12,[[],["result",4]]],[11,"try_into","","",12,[[],["result",4]]],[11,"borrow_mut","","",12,[[]]],[11,"type_id","","",12,[[],["typeid",3]]],[11,"from","smc::group","",7,[[]]],[11,"into","","",7,[[]]],[11,"borrow","","",7,[[]]],[11,"try_from","","",7,[[],["result",4]]],[11,"try_into","","",7,[[],["result",4]]],[11,"borrow_mut","","",7,[[]]],[11,"type_id","","",7,[[],["typeid",3]]],[11,"from","","",8,[[]]],[11,"into","","",8,[[]]],[11,"borrow","","",8,[[]]],[11,"try_from","","",8,[[],["result",4]]],[11,"try_into","","",8,[[],["result",4]]],[11,"borrow_mut","","",8,[[]]],[11,"type_id","","",8,[[],["typeid",3]]],[11,"commit","smc::commitment::elgamal","Computes the commit as a tuple (c1, c2), where c1 = g^r…",0,[[["bignum",3]],[["errorstack",3],["result",4]]]],[11,"verify","","",0,[[["opening",3],["commit",3]],[["result",4],["errorstack",3]]]],[11,"commit","smc::commitment::pedersen","Generates a commit c = g^r * h^m, for a given message m.",3,[[["bignum",3]],[["result",4],["errorstack",3]]]],[11,"verify","","",3,[[["commit",6],["opening",3]],[["result",4],["errorstack",3]]]],[11,"get_generator","smc::group","Caution: this method `panics!`",7,[[],["ecpoint",3]]],[11,"get_order","","Get the order of the group.",7,[[],["bignum",3]]],[11,"generate_random_element","","Generates a random element in the group.",7,[[],["ecpoint",3]]],[11,"generate_random_exponent","","Generates a random exponent.",7,[[],["bignum",3]]],[11,"exponentiate","","Despite its name, this method performs a multiplication on…",7,[[["ecpoint",3],["bignum",3]],["ecpoint",3]]],[11,"multiply","","Indeed it returns an `Ecpoint x = e1 + e2`.",7,[[["ecpoint",3]],["ecpoint",3]]],[11,"pow","","Despite its name, this method performs a multiplication…",7,[[["bignum",3]],["ecpoint",3]]],[11,"eq","","",7,[[["ecpoint",3]]]],[11,"get_generator","","",8,[[],["bignum",3]]],[11,"get_order","","returns a copy!",8,[[],["bignum",3]]],[11,"generate_random_element","","",8,[[],["bignum",3]]],[11,"generate_random_exponent","","",8,[[],["bignum",3]]],[11,"exponentiate","","",8,[[["bignum",3]],["bignum",3]]],[11,"multiply","","",8,[[["bignum",3]],["bignum",3]]],[11,"pow","","",8,[[["bignum",3]],["bignum",3]]],[11,"eq","","",8,[[["bignum",3]]]],[11,"fmt","smc::commitment::elgamal","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",10,[[["formatter",3]],["result",6]]],[11,"fmt","","",11,[[["formatter",3]],["result",6]]],[11,"fmt","smc::commitment::pedersen","",3,[[["formatter",3]],["result",6]]],[11,"fmt","","",12,[[["formatter",3]],["result",6]]],[11,"fmt","smc::group","",7,[[["formatter",3]],["result",6]]],[11,"fmt","","",8,[[["formatter",3]],["result",6]]]],"p":[[3,"Committer"],[6,"Committer"],[6,"Committer"],[3,"Committer"],[6,"Committer"],[6,"Committer"],[8,"Committer"],[3,"EllipticCurveGroup"],[3,"MultiplicativeGroup"],[8,"DLogGroup"],[3,"Commit"],[3,"Opening"],[3,"Opening"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);