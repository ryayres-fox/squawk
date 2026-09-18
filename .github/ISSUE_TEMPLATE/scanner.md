---
name: Scanner integration
about: Drive a scanner Squawk does not drive yet
labels: scanner
---

### The scanner

Name, licence, and what it finds that nothing already integrated does.

### The six questions

From `CONTRIBUTING.md`. A "no" is not a blocker; it is a thing to write down.

1. **What does it claim?**
2. **How would a reader check it?**
3. **What does it look like when the scanner is broken?** If that looks the
   same as a clean result, it cannot ship.
4. **What does it not cover?**
5. **What is its identity, and is it portable?** No timestamps, paths or hosts.
6. **What evidence does it leave?**

### Its output

A small real sample, and whether the format is stable between versions.

### Its denominator

What the scanner reports about how much it examined. A zero over an empty
denominator is not a clean result (I15), so a scanner that cannot say what it
looked at needs a plan for that.
