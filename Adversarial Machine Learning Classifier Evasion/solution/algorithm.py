#!/usr/bin/env python3
"""
Real solver for misc_02_adversarial_ml_feature_perturbation.

Reads ONLY dist/model_weights.json. The model is a binary linear classifier
score(x) = w.x + b with decision boundary score = 0. x_input is classified
"authorised" (score > 0). The unique minimal-L2 perturbation that moves it onto
the decision boundary is the orthogonal projection:

        delta* = -((w.x_input + b) / ||w||^2) * w
        x_adv  = x_input + delta*

x_adv is the gateway's secret enrolment template: an ASCII byte vector. Rounding
to the nearest integers and decoding yields the flag.

Note: a sign-based (L-infinity / FGSM) step does NOT land on byte values, so the
exact L2 projection is required.

Does not contain the flag and never reads the ./flag file.
"""
import argparse
import json
import os
import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    with open(os.path.join(args.dist, "model_weights.json"), "r", encoding="utf-8") as f:
        m = json.load(f)
    w = np.array(m["weights"], dtype=np.float64)
    b = float(m["bias"])
    x = np.array(m["x_input"], dtype=np.float64)

    # orthogonal projection of x onto the hyperplane w.y + b = 0
    delta = -((w @ x + b) / (w @ w)) * w
    x_adv = x + delta

    recovered = np.rint(x_adv).astype(int)
    flag = bytes(int(c) & 0xFF for c in recovered).decode()
    print(flag)


if __name__ == "__main__":
    main()
