
CardinalityHBC
(Cardinality set-intersection protocol for the honest-but-curious case.)

Author: Yuye 
Date: Dec 2013

Implementation of Algorithm come from paper:
Kissner, L., & Song, D. (2005, January). Privacy-preserving set operations. In Advances in Cryptology–CRYPTO 2005 (pp. 241-257). Springer Berlin Heidelberg.
Cardinality set-intersection protocol for the honest-but-curious case. (Algorithm shown in Figure 2)


Each peer has a file contianing multiple integers. This project will allow multiple nodes to get the number of integers that are in common without letting other peers to know the values they have. 

Language: Python
UDP for communication between peers. 
Paillier cyptosystem is used. 

Scale:
Works with small values, such as integers 0 to 9. Tested using 5 nodes. 

How to run:

1. Open a first node: python CardinalityHBC first
2. Open several nodes: python CardinalityHBC
3. Connect every node with the first node, by type in the address. A sequence number will be signed to each node. 
4. After all nodes are connected, in first node type in "s" to start the algorithm
5. Enter "q" to quit

