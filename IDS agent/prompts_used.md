# AI-Assisted Development — Prompts Used

As required by the assignment ("AI can be used but the prompts used to
develop the solution for the case study should be attached"), this is the
sequence of prompts given to the AI assistant (Claude) during the design and
development of this project, in order.

1. Described the FoAI case-study brief (design document, environment/agents/
   AI strategy, coding phase, small-scale analysis, viva) and initially asked
   about combining it with Huffman coding.

2. After discussing Huffman coding's fit for the assignment, asked for a
   full downloadable project (design doc, code, UI) for a rule-based
   Huffman/RLE text-compression agent.

3. Asked how to run the resulting project (Python + browser UI) from
   scratch, including basic command-line navigation.

4. Asked clarifying questions about the compression agent's decision logic
   (how RLE vs. Huffman vs. no-compression is chosen, how entropy is
   calculated, and why specific threshold values — 32 chars, 8 average run
   length, 95% entropy ratio — were used).

5. After reflecting that the compression topic felt like a stretch for an
   "AI" project, asked for an entirely different topic. Was offered a choice
   between search/pathfinding (A*), game-playing (Minimax), CSP solving
   (Sudoku), and reinforcement learning (Q-learning); replied "anything
   fine" to let the assistant pick.

6. After A* pathfinding was built and demonstrated (BFS vs. Dijkstra vs. A*
   node-expansion comparison), said A* felt too basic and asked for a
   different topic — but asked the assistant to choose a topic based on
   genuine fit/interest first, rather than presenting an algorithm menu to
   pick from.

7. In response, the assistant proposed a topic grounded in the user's own
   research background (federated learning / network intrusion detection):
   an "Intelligent Network Intrusion Detection Agent." Asked whether it
   would be difficult to build.

8. Clarified that no external dataset should be used — asked for the same
   rule-based (not dataset/ML-trained) approach used in the earlier
   compression project, applied to network traffic instead.

9. Asked the assistant to build the full project.

## Notes on how AI output was used

- The AI proposed the rule-based "Sense → Decide → Act" architecture and the
  specific decision rules (R1–R5) for classifying network connections; these
  were implemented and verified (Python `agent.py` and the browser UI's
  JavaScript were cross-checked against each other for matching output, and
  the analysis script was run to confirm all five sample traffic profiles
  classify as expected) as part of this submission.
- The specific numeric thresholds (5 failed logins, 15 hosts, 5 MB, 20
  connections/second) are heuristic choices, not fitted to real traffic
  data — this is disclosed explicitly in `design_document.md`, section 5.
- All code in `python/` and `web-ui/` should be read, understood, and be
  ready to be explained/defended in the viva — including why each decision
  rule exists, what real attack behavior it approximates, and what would
  change if it were replaced with a learned classifier.
