# Lattice Signature Without Trapdoor

> this is a simple notes about the Paper _Lattice Signature Without Trapdoor_ and used for the advanced cryptography

## Overview

1. No "hash-and-sign" methodology
   1. secure in random oracle: $H:{0, 1}^k → {\bold{v}: \bold{v} \in {-1, 0, 1}^k, ||\bold{v}|| \leq k}$ model
   2. worst-case hardness of SIVP
2.
   1. smaller sk, pk, signature size
   2. simpler signing algorithm: matrix-vector multiplications and rejection samplings
3.
   1. changing parameter: more efficient signatures: based on LWZ

## 1 Introduction

### contributions:

1. adapting the ring-SIS based scheme to one based on the hardness of the regular SIS problem, which results in signatures of the same $\tilde{O}(n^{1.5})$ length
2. reduce the signature length to $\tilde{O}(n)$
3. show the parameter of the scheme can be set s.t. the resulting scheme produces much shorter signatures Def2.1: signature scheme Def2.2: security forger

## 3. SIS Problems and Variants

Def3.1: $l\_2-SIS\_{q,n,m,\beta}$ problem Def3.2: $SIS\_{q,n,m,d}$ distribution Def3.3

### tradition

#### scheme

signature scheme for msg space $\mathcal{X}$, tuple of PPT algor\_ ($\mathsf{KGen, Sign, Vf}$), with syntax:

* $(\mathsf{pk, sk}) \leftarrow \mathsf{KGen}(1^\lambda)$
* $\sigma \leftarrow \mathsf{Sign(sk}, x); x\in \mathcal{X}$
* $b \leftarrow \mathsf{Vf}(\mathsf{bk}, x, σ)$

#### correctness

$$
\Pr\left[\mathsf{Vf}(\mathsf{pk}, x, \sigma) = 1 \bigg| \begin{aligned} (\mathsf{pk, sk}) \leftarrow \mathsf{KGen}(1^\lambda) \\ \sigma \leftarrow \mathsf{Sign(sk},x) \end{aligned}\right] \geq 1 - \mathsf{negl}(\lambda)
$$

#### EUF-CMA security:

$\Sigma = (\mathsf{KGen, Sign, Vf})$ for $\mathcal{X}$ is "Essentially UnForgeable against Chosen Message Attack", if $\forall PPT \mathcal{A}$

$$
\Pr[\text{EUF-CMA}_{\Sigma, \mathcal{A}}(1^\lambda) = 1] \leq \mathsf{negl(\lambda)}
$$

$$
\underline{\text{EUF-CMA}_{\Sigma, \mathcal{A}}(1^\lambda):} \\ S := \Phi; \\ (\mathsf{pk, sk}) \leftarrow \mathsf{KGen}(1^\lambda); \\ (x^*, \sigma^*) \leftarrow \mathcal{A}^{\mathsf{Sign}\mathscr{O}}(\mathsf{pk}) \\ \mathsf{return(Vf(pk, \mathcal{x}^*, \sigma^* ) = 1) }\land (x^* \notin T)
$$

$$
\underline{\mathsf{Sign}\mathscr{O}(x):} \\ \text{if}\quad S[x] = \text{null} \quad \text{then}: \\ \quad S[x] := \sigma \leftarrow \mathsf{Sign(sk, \mathcal{x})} \\ \text{return} \quad S[x]
$$

#### GPV Signature

$$
\underline{\mathsf{KGen(1^\lambda)}}: \\ \begin{aligned} & (\bold{A}, \mathsf{td}) \leftarrow \mathsf{TrapGen} (1^\lambda) \\ &(\mathsf{pk, sk}) := (\bold{A}, \mathsf{td}) \\ & \mathsf{return (pk, sk)} \end{aligned}
$$

$$
\underline{\mathsf{Sign(sk, \mathcal{x})}}: \\ \begin{aligned} & \mathbf{v} := H(x) \\ & \mathbf{u} ← \mathsf{SamplePre}(\mathsf{td}, \mathbf{v}) \\ & \sigma := \mathbf{u} \\ & \mathsf{return} \sigma \end{aligned}
$$

$$
\underline{\mathsf{Vf(pk, \mathcal{x}, \sigma)}:} \\ \begin{aligned} & \mathbf{v} := H(x) \\ & b_0 := (\mathbf{Au = v} \mod q) \\ & b_1 := (||\mathbf{u}|| \leq \beta) \\ & \mathsf{return} b_0 \land b_1 \end{aligned}
$$

### New scheme:

$$
\mathsf{sk} : \mathbf{S} \in \mathbb{Z}_q^{m\times k} \\ \mathsf{pk}: \mathbf{A} \in \mathbb{Z}_q^{n \times m}; \mathbf{T} = \mathbf{A \cdot S} \mod q
$$

where $\mathbf{A}$ is shared and $\mathbf{S}$ is individual

$$
\mathsf{Sign}: \\ \begin{aligned} & \mathbf{y} \leftarrow\$ \mathbb{Z}_q^m; \mathcal{D} \\ & \mathbf{c} ← H(\mathbf{Ay} \mod q, \mu), \mathbf{c} \in \mathbb{Z}_ q^k ; \\ & \mathbf{z} \leftarrow \mathbf{Sc + y}; \\ & \text{do some stuff} \\ &\mathsf{return} \mathbf{c, z}; \end{aligned}
$$

choosing $f, \mathcal{D}$ m-dimensional Normal distribution with standard variation as $\sigma = \tilde{\Theta}(v) = \tilde{\Theta}(\sqrt{m})$

### Organization

* Sec3: avg-case SIS & variants (security basis)
* Sec4: Normal Distribution and rejection sampling: prove statistically indistinguishablitiy
* Sec5: construct a signature secure
* Sec6: modify: SIS-> LWE
* Sec7: Ring Setting

## 2. Preliminaries

### 2.1

* $q$: small (polynomial-size) prime number
* $\mathbb{Z\_q}: \[-\frac{q-1}{2}, \frac{q-1}{2}]$
* $\mathbf{v}$: all column vectors
* $l\_p \text{norm}: ||\mathbf{v}||\_p$, omit $p$ if $p=2$
* $\mathcal{D}$: distribution, $x \leftarrow$\mathcal{D}$: $x$ is chosen according to dist\_ $\mathcal{D}$
* $\mathcal{S}$: set, $x \leftarrow$\mathcal{S}$: $x$ is chosen uniformly at random from $\mathcal{S}$
* $\mathbf{E}$: Event $\Pr\[\mathbf{E}; x\_1 \leftarrow$ \mathcal{D}, ......, x\_k \leftarrow \mathcal{D}\_k]$

### 2.2 Digital Signatures

Def2.1: signature scheme Def2.2: security forger

## 3. SIS Problems and Variants

Def3.1: $l\_2-SIS\_{q,n,m,\beta}$ problem: Def3.2: $SIS\_{q,n,m,d}$ distribution: Def3.3: $SIS\_{q,n,m,d}$ search problem Def3.4: $SIS\_{q,n,m,d}$ decision problem

Def3.1: $l\_2-SIS\_{q,n,m,\beta}$ problem:  given $\mathbf{A} \leftarrow $ \mathbb{Z}_q^{n\times m}$, find $\mathbf{v} \in \mathbb{Z}^m \setminus {0} \land ||\mathbf{v}|| \leq \beta$ Def3.2: $SIS_{q,n,m,d}$ distribution:  $\mathbf{A} \leftarrow $ \mathbb{Z}_q^{n\times m}$, $\mathbf{s} \leftarrow $ {-d,..., 0, ..., d}^m$, output $(\mathbf{A, As})$ Def3.3: $SIS_{q,n,m,d}$ search problem  given $\mathbf{(A, t)}$, find $\mathbf{s}$, s.t. $\mathbf{As=t} $ Def3.4: $SIS\_{q,n,m,d}$ decision problem  given $\mathbf{(A, t)}$, decide whehter it is from $SIS$ dist, or uniformly at random from $\mathbb{Z}\_q^{n×m} \times \mathbb{Z}\_q^n$ when $d \ll q^{\frac{n}{m\}}$: low density problem when $d \gg q^{\frac{n}{m\}}$: high density problem when $d == q^{\frac{n}{m\}}$: hardest Reduce to $\mathbf{A} = \[\mathbf{\bar{A\}} || \mathbf{I}], \mathbf{\bar{A\}} ←\mathcal{U} \mathbb{Z}\_q^{n × (m - n)}$, called "_Hermite Normal Form_"

### 3.1 Relation Between the SIS variants

Thrm3.5 sSIS redution to dSIS Lem3.6 dSIS size reduction Lem3.7 dSIS reduction to l2SIS

Thrm3.5 sSIS redution dSIS:  $sSIS\_{q,n,m,d} \stackrel{\text{polytime}(\mathcal{n})\text{reduction\}}{\longrightarrow} dSIS\_{q,n,m,d}; d\in\text{poly}(n)$ Lem3.6 dSIS size reduction:  $\forall \alpha \in \mathbb{Z}^+, s.t. \gcd(2\alpha + 1, q) = 1; \exists r \in \text{poly}(n): s.t. dSIS\_{q,n,m,d}\stackrel{r}{\longrightarrow} dSIS\_{q,n,m,(2\alpha + 1)d + \alpha}$ Lem3.7 dSIS reduction l2SIS:  if $m=2n \land 4d\beta\sqrt{m} \leq q, \exists r\in \text{poly}(n), dSIS\_{q,n,m,d} \stackrel{r}{\longrightarrow}l\_2-SIS\_{q,n,m,\beta}$

## 4 Rejection Sampling and the Normal Distribution

Def4.1: continuous Gaussian Def4.2: Discrete Gaussian Lem4.3: Discrete Gaussian vector inner product probability bound Lem4.4: bound of Discrete Gaussian value and the probability of its value range Lem4.5: bound of Discrete Gaussian quotient Thrm4.6: main Therom Lem4.7: generation distance

Def4.1: continuous Gaussian

$$
ho_{\mathbf{v},\sigma}^{m}(\mathbf{x}) = (\frac{1}{\sqrt{2\pi\sigma^2}})^m e^{-\frac{||\mathbf{x - v}||^2}{2\sigma^2}}
$$

Def4.2: Discrete Gaussian

$$
D_{\mathbf{v}, \sigma}^m(\mathbf{x}) = \rho_{\mathbf{v},\sigma}^{m}(\mathbf{x}) / \rho_{\sigma}^{m}(\mathbb{Z}^m) ; \rho_{\sigma}^{m}(\mathbb{Z}^m) = \Sigma_{\mathbf{z}\in\mathbb{Z}^m}\rho_{\sigma}^{m}(\mathbf{z})
$$

Lem4.3: Discrete Gaussian vector inner product probability bound

$$
\forall \mathbf{v} \in \mathbb{R}^m, \forall \sigma, r > 0; \\ \Pr[|<\mathbf{z, v}>| > r; \mathbf{z} \stackrel{\$}{\longleftarrow}D_{\sigma}^m] \leq 2 e^{-\frac{r^2}{2||\mathbf{v}||^2 \sigma^2}}
$$

Lem4.4:

1. $\forall k > 0, \Pr\[|z| > k\sigma; z\stackrel{$}{\longleftarrow}D\_{\sigma}^{1}] \leq 2 e^{-\frac{k^2}{2\}}$
2. $∀ \mathbf{z}∈\mathbb{Z}^m \land σ \geq 3\sqrt{2\pi}, D\_\sigma^m(\mathbf{z}) \leq 2^{-m}$
3. $\forall k > 1, \Pr\[||\mathbf{z}|| > k\sigma\sqrt{m}; \mathbf{z}\stackrel{$}{\longleftarrow} D\_{\sigma}^{m}] \leq k ^m \cdot e^{\frac{m}{2}(1 - k^2)}$

Lem4.5:

$$
\forall \mathbf{v} \in \mathbb{Z}^m, \text{if} \sigma=\omega(||\mathbf{v}||\sqrt{\log m}) \quad \text{then}: \\ \Pr[D_{\sigma}^m(\mathbf{z})/D_{\mathbf{v},\sigma}^m(\mathbf{z}) = O(1); \mathbf{z}\stackrel{\$}{\longleftarrow}D_{\sigma}^m] = 1 - 2^{\omega(\log m)} \\
$$

i.e.

$$
\forall \mathbf{v} \in \mathbb{Z}^m, \text{if} \sigma=\alpha ||\mathbf{v}||, \forall \alpha > 0 \quad \text{then}: \\ \Pr[D_{\sigma}^m(\mathbf{z})/D_{\mathbf{v},\sigma}^m(\mathbf{z}) < e^{\frac{12}{\alpha} + \frac{1}{2\alpha^2}}; \mathbf{z}\stackrel{\$}{\longleftarrow}D_{\sigma}^m] = 1 - 2^{-100} \\
$$

Thrm4.6: main Therom if $V \in \mathbb{Z}^m; \forall \mathbf{v} \in V, ||\mathbf{v}|| < T; \sigma \in \mathbb{R}; \sigma = \omega(T\sqrt{\log m})$ then:

$$
\exist \text{constant}M = O(1); \\ s.t. \text{the distribution of following algo} \mathcal{A}:
$$

1. $\mathbf{v} \stackrel{$}{\longleftarrow} h$
2. $\mathbf{z} \stackrel{$}{\longleftarrow} D\_\sigma^m$
3.  output $(\mathbf{z, v})$ with probability $\min(\frac{D\_\sigma^m(\mathbf{z})}{M D\_{\mathbf{v}, \sigma}^m(\mathbf{z})}, 1)$

    is within statistical distance $\frac{2^{-\omega(\log m )\}}{M}$ of the distribution of following algo. $\mathcal{F}$

    1. $\mathbf{v} \stackrel{$}{\longleftarrow} h$
    2. $\mathbf{z} \stackrel{$}{\longleftarrow} D\_\sigma^m$
    3. output $(\mathbf{z, v})$ with probability $\frac{1}{M}$ if $\sigma = \alpha T, \forall \alpha > 0; M = e^{\frac{12}{\alpha} + \frac{1}{2\alpha^2\}}$, $Δ(\mathcal{A, F}) \leq \frac{2^{-100\}}{M}$;

Lem4.7: set $V$, probability distribution $h: V → R$;$f:\mathbb{Z}^m → R$ if: $g\_v: \mathbb{Z}^m → \mathbb{R}$: family of probdist, indexed by $v \in V$, s.t.   $∃M \in \mathbb{R}$, s.t. $\forall v \Pr\[Mg\_v(z) ≥ f(z); z\stackrel{$}{←}f]≥ 1 - ϵ$; then: $\mathcal{A}$  

1. $\mathbf{v} \stackrel{$}{\longleftarrow} h$
2. $\mathbf{z} \stackrel{$}{\longleftarrow} g\_v$
3. output $(\mathbf{z, v})$ with probability $\min(\frac{f(\mathbf{z})}{M g\_v(\mathbf{z})}, 1)$

$\mathcal{F}$

1. $\mathbf{v} \stackrel{$}{\longleftarrow} h$
2. $\mathbf{z} \stackrel{$}{\longleftarrow} D\_\sigma^m$
3. output $(\mathbf{z, v})$ with probability $\frac{1}{M}$

$\Delta(\mathcal{A, F}) ≤ \frac{\epsilon}{M}$;

## 5.Signature Scheme Based on SIS

main result: "a signature scheme based (in the random oracle model) on the average hardness of the $l\_2$-$SIS\_{q,n,m,β}$problem for $\beta = \tilde{O}(n)$"

Signing key: $\mathbf{S} \stackrel{$}{←} {-d, ...,0,..., d}^{m × k}$ (i.e. secret key) Verification key: $\mathbf{A} \stackrel{$}{←} \mathbb{Z}\_q^{n \times m}, \bold{T} ← \mathbf{AS}$ (i.e. public key) Random Oracle: $H:{0, 1}^k → {\bold{v}: \bold{v} \in {-1, 0, 1}^k, ||\bold{v}|| \leq k}$ Thrm5.1 break signature → solve $l\_2$-SIS with prob Lem5.2 collision of SIS Lem5.3 distinguish real sign algo and hyb2 Lem5.4 forging w.p menas solve SIS $\mathsf{Sign}(μ, \bold{A, S})$

1. $y \stackrel{$}{←} D\_{σ}^m$
2. $\bold{c} \leftarrow H(\bold{Ay}, \mu)$ //hash function outputs 100 bits
3. $\bold{z} ← \bold{Sc + y}$
4. Output $(\bold{z, c})$ with probability $\min(\frac{D\_\sigma^m(\bold{z})}{M D\_{\bold{v}, \sigma}^m(\bold{z})}, 1)$ //$\bold{(z, c)}$ independent of $\bold{S}$

$\mathsf{Verify}(μ, \bold{z,c,A, T})$:

1. Accept iff: $||\bold{z}|| ≤ ησ\sqrt{m} \land \bold{c} = H(\bold{Az - Tc}, μ)$

Thrm5.1 if there is a PPT forger, makes at most $s$ queries to signing oracle and $h$ queries to random oracle $\mathcal{H}$, and break signature above w.p. $δ$, then $\exists$ PPT algo. solve $l\_2$-$SIS\_{q,n,m,β}$ for $β = (2\eta\sigma + 2 d\kappa)\sqrt{m} = \tilde{O}(dn)$ w.p $=\frac{\delta^2}{2(h + s)}$ above signing produces signature w.p. $\frac{1}{M}$ and verify authenticate signature w.p. $≥ 1 - \frac{1}{2^m}$;

Lem5.2 $\forall \mathbf{A} \in \mathbb{Z}\_q^{n ×m }, m > 64 + n ⋅ \frac{\log q}{\log(2d + 1)}, \forall \mathbf{s} \stackrel{$}{←}{ -d, ..., 0, ..., d}^m$, w.p. $1 - \frac{1}{2^{100\}}$, $\exist \bold{s'} \in \stackrel{$}{←}{ -d, ..., 0, ..., d}^m$ s.t. $\bold{As = As'}$ Lem5.3 distinguisher $\mathcal{D}$ can query random oracle $\mathcal{H}$, either actual signing algo. or Hybrid2, if it queries $\mathcal{H} h$ times, signing algo $s$ times, $\forall$ but a $e^{-\Omega(n)}$ fraction of all possible matrices $\mathbf{A}$. his advantage of distinguishing signing algo from Hyb2 $≤ s(h + s)\frac{2}{2^n} + s \frac{2^{-100\}}{M} = s(h + s)\frac{2}{2^n} + s \frac{2^{-\omega(\log m )\}}{M}$

$$
\underline{\text{Hyb1}}:\\ \mathsf{Sign}(\mu, \mathbf{A, S})
$$

1. $\mathbf{y} \stackrel{$}{←} \mathcal{D}\_\sigma^m$
2. $\mathbf{c} \stackrel{$}{←}{\bold{v}: \bold{v} \in {-1, 0, 1}^k, ||\bold{v}|| \leq k}$
3. $\bold{z} ← \bold{Sc + y}$
4. w.p. $\min(\frac{D\_\sigma^m(\bold{z})}{M D\_{\bold{Sc},\sigma}^m(\bold{z})}, 1)$
5. output $\bold{(z,c)}$
6. program $\mathcal{H}(\bold{Az - Tc}, \mu) = \bold{c}$

$$
\bold{Az - Tc} = \bold{A(Sc + y) - Tc} = \bold{Asc + Ay - Tc} = \bold{Tc + Ay - Tc} = \bold{Ay}
$$

$$
\underline{\text{Hyb2}}:\\ \mathsf{Sign}(\mu, \mathbf{A, S})
$$

1. $\mathbf{c} \stackrel{$}{←}{\bold{v}: \bold{v} \in {-1, 0, 1}^k, ||\bold{v}|| \leq k}$
2. $\bold{z} \stackrel{$}{←} \mathcal{D}\_\sigma^m$
3. w.p. $\frac{1}{M}$
4. output $\bold{(z,c)}$
5. program $\mathcal{H}(\bold{Az - Tc}, \mu) = \bold{c}$

Lem5.4 Suppose $\exist$ PPT forger $\mathcal{F}$, makes $≤ h$ queries to signer in Hyb2, $≤$ s queries to $\mathcal{H}$, succeeds in forging w.p, $δ$ Then $\exist$ algo of same time-complexity as $\mathcal{F}$ s.t. for given $\bold{A} \stackrel{$}{←} \mathbb{Z}\_q^{n × m}$, finds $\bold{v} \in \mathbb{Z}^m,$ s.t. $||\bold{v}|| ≤ (2ησ + 2dκ)\sqrt{m}$ and $\bold{Av}= 0$, w.p. $≥ (\frac{1}{2} - 2^{-100})(\delta - 2^{-100})(\frac{\delta - 2^{-100\}}{h + s} - 2^{-100})$

## 6 Signatures Based on Low-Density SIS and LWE

Signing key: $\mathbf{S} \stackrel{$}{←} {-d', ...,0,..., d'}^{m × k}$ (i.e. secret key) Verification key: $\mathbf{A} \stackrel{$}{←} \mathbb{Z}\_q^{n \times m}, \bold{T} ← \mathbf{AS}$ (i.e. public key)

$$
\underline{\text{Hyb3}}:\\ \mathsf{Sign}(\mu, \mathbf{A, S})
$$

1. $\mathbf{c} \stackrel{$}{←}{\bold{v}: \bold{v} \in {-1, 0, 1}^k, ||\bold{v}|| \leq k}$
2. $\bold{z} \stackrel{$}{←} \mathcal{D}\_\sigma^m$
3. w.p. $\frac{1}{M}$
4. output $\bold{(z,c)}$
5. program $\mathcal{H}(\bold{Az - Tc}, \mu) = \bold{c}$

Lem6.1 distingusher $\mathcal{D}$ query $\mathcal{H}$ $h $ times and acutual signing algo or Hyb3 $s$ times, if distinguish Hyb3 w.p, $δ$, then $\mathcal{D}$ solve $dSIS\_{q,n,m,d}$ w.p. $Ω(\frac{\delta}{k}) - (s(h+s)\frac{2}{2^n} + s \frac{2^{-\omega(\log m)\}}{M})$ Lem6.2 PPT Forger $\mathcal{F}$, given verkey, access signing algo $h$ times, random oracle $\mathcal{H}$ $s$ times, success in forging w.p. $δ$ → ∃ algo of same PPT as $\mathcal{F}$, given $\bold{A} \stackrel{$}{←} \mathbb{Z}\_q^{n × m}$, finds $\bold{v} \in \mathbb{Z}^m,$ s.t. $||\bold{v}|| ≤ (2ησ + 2dκ)\sqrt{m}$ and $\bold{Av}= 0$, w.p. $≥ (\frac{1}{2} - 2^{-100})(\delta - 2^{-100})(\frac{\delta - 2^{-100\}}{h + s} - 2^{-100})$

### 6.1 LWE-Problem

$\bold{a}\_i \stackrel{\mathcal{U\}}{←} \mathbb{Z}\_q^n; b\_i = \bold{a}\_i \bold{s}\_i + e\_i, \bold{s} \in \mathbb{Z}\_q^n$ is secret, $e\_i$ error of small absolute values $dLWE: (\bold{a}\_i, b\_i)$ is generated or from uniform distribution if $\bold{A=\[\bar{A} || I]} \in \mathbb{Z}\_q^{n × 2n}, \bold{\bar{A\}} \stackrel{$}{←} \mathbb{Z}_q^{n × n}; (\bold{A, As}), \bold{s}\stackrel{$}{←} D_{\psi}^{2n}$ uni\_dist is LWE

## 7 Ring Variants

reduce key sizes by $k$; makes matrices "not independent" $\bold{A} = \[\bold{a}\_0,\bold{a}_1,......,\bold{a}_{n - 1}] \in \mathbb{Z}\_q^{n \times m}$ let $\bold{a}_1,......,\bold{a}_{n - 1}$ be coefficient representation of the polynomial $\bold{a}\_0\bold{x}^i$ in the ring $\mathbb{Z}\_q\[\bold{x}]/\langle\bold{f}\rangle$ for some univariate polynomial $\bold{f} \langle \bold{x} \rangle$ of degree $n$

secret key $\bold{s}_1,......,\bold{s}_{γ} \in \mathbb{Z}\_q\[\bold{x}]/\langle \bold{x}^n + 1 ⟩$; $\bold{s}\_i \stackrel{$}{←} i.d.d. {-d,...,0,...,d}$ pk: $(\bold{a}_1,......,\bold{a}_{γ}, t), \bold{s}\_i \stackrel{$}{←} \mathbb{Z}_q\[\bold{x}]/\langle \bold{x}^n + 1 ⟩, t = \sum_{i=1}^γ \bold{a}\_i\bold{s}\_i$

1. $\bold{y}_1,......,\bold{y}_{γ} \stackrel{$}{←} D\_\sigma^n$
2. $\bold{c} = H(\sum\_{i=1}^γ \bold{a}\_i, μ)$
3. $\bold{z}\_i ← \bold{s}\_i \bold{c}\_i + \bold{y}\_i$ for $i ∈ \[γ]$
4. output $(\bold{z}_1,......,\bold{z}_{γ}) w.p. \min(\frac{D\_\sigma^m(\bold{\bar{z\}})}{M D\_{\bold{\bar{v\}},\sigma}^m(\bold{\bar{z\}})}, 1)$

$\bold{\bar{z\}} = \[\bold{z}\_1^T || ... || \bold{z}\_γ^T]^T$ $\bold{\bar{v\}} = \[(\bold{s}\_1\bold{c})^T || ... || (\bold{s}\_γ\bold{c})^T]^T$ verification checks: $||\bold{\bar{z\}}|| \leq 2σ\sqrt{m}$; $\bold{c} = H(\bold{a}\_1\bold{z}\_1, ...., \bold{a}\_γ\bold{z}\_γ - \bold{tc}, \mu)$
