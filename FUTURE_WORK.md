# Future work

Ideas for extending the testbed. The threat model stays the same: planted text in data the
agent reads tries to trigger an unauthorized action on fake `.test` data, or to corrupt what the
user is told, and the question is which defenses stop that without breaking the user's task.

## 1. Where planted text can arrive (carriers)

The current testbed plants text in three places: an email body, a file, and a calendar event
description. Real assistants read far more surfaces. Each one below is a new `carrier` type, and
for each the interesting question is the same: **does a given detector or defense even see it?**

| carrier | example | does a text-only LLM detector see it? |
|---|---|---|
| email body | today's attacks | yes |
| subject line, sender display name | LLMail-Inject submissions often used the subject | only if the subject is passed to it |
| quoted reply / forwarded thread | text sits deep in an old message the user never reads | yes, but it is easy to truncate away |
| signature or footer | appended by a mailing list or a compromised account | yes |
| hidden HTML (white text, zero-size font, comments) | invisible to the human, visible to the model | yes, if HTML is passed through; no, if it is stripped first |
| invisible Unicode (zero-width or tag characters) | the human sees nothing at all | depends on tokenizer and preprocessing |
| **attachment: PDF / DOCX / spreadsheet** | text in the document body, comments, cells, metadata | only after the attachment is parsed; the parser decides what survives |
| **attachment: image** | text rendered inside a picture, or in alt text | **no** — needs OCR or a vision model; this is the multimodal case |
| **calendar invite (.ics)** | an email arrives with an invite; the instruction is in the event description or location, and is read later when the assistant opens the calendar | only when the calendar tool is read; the email itself can look clean |
| link / reference in the email | the email is clean but points to a page or shared document whose content is fetched | only the fetched content carries it; the email detector sees nothing |
| shared document comments, file names, contact cards | small fields assistants read without the user noticing | rarely checked |

### The calendar case you asked about

Yes, this is possible, and it is a real-world pattern: researchers have shown attacks on production
assistants through calendar invitations (Nassi et al., 2025, "Invitation Is All You Need"). Our
testbed already has a small version of it: `pivot-calendar-to-email` plants the text in a calendar
event and the attacker's goal is an email. The interesting extension is the **two-hop** version:

1. An email arrives with a meeting invite. The email body is harmless, so a detector on the email passes it.
2. Later, the user asks "what's on my calendar?". The assistant reads the event description, where
   the planted text sits.
3. The question: is the second read checked at all, and does a defense that only looks at emails miss it?

This tests **where in the pipeline defenses are placed**, not just how strong they are.

## 2. Multi-step and delayed attacks

- **Chains across tools:** email → calendar → action, or file → email. Measure ASR per hop.
- **Delayed trigger:** the planted text only matters when a later, unrelated task reads it.
- **Persistence:** the agent writes attacker text into notes or memory, so it affects future sessions.
- **Two-stage data theft** (the useful concept from InjecAgent): stage 1 reads private data, stage 2
  sends it out. Score both stages separately: a defense may allow the read but stop the send.

## 3. Multimodal carriers (images, scanned PDFs)

- Use a local vision-language model (for example a Qwen VL model through Ollama) as the agent, and
  attach images to fake emails.
- Compare three pipelines: (a) text detector only, (b) OCR the image, then the text detector, (c) a
  vision model as the detector.
- Expected finding to test: text-only detectors are blind to image carriers, so the detector's ASR
  rises sharply for the same attack moved into an image.
- Cost: vision models are much slower on this CPU-only laptop; a small pilot is realistic, a full sweep is not.

## 4. Better attackers (concepts from the dropped datasets)

LLMail-Inject and InjecAgent were removed because their raw attacks were written for other models
and tools and almost never transferred here (0 of 10 and 0 of 7 undefended). What is worth keeping
from them is the method, not the texts:

- **Adaptive attacker** (LLMail-Inject): attackers saw which defense they faced and iterated. A
  research version: give an attacker model a few attempts per defense and report ASR after k tries,
  instead of a single fixed attempt.
- **Base vs enhanced setting** (InjecAgent): run the same attack with and without a forceful framing
  sentence, to separate "the model follows instructions in data" from "the model was pushed hard".
- **Stage-wise scoring** (InjecAgent): see section 2.

## 5. Better defenses to compare

- **Provenance tracking** (CaMeL, Debenedetti et al., 2025): tag every value with where it came from
  and block untrusted values from flowing into sensitive arguments. Our Dual LLM sink rule is a
  one-line version of this.
- **Detector placement:** run the detector on every carrier type (attachments, invites, fetched
  links), not only on what read tools return directly.
- **Per-modality detectors:** OCR + text detector vs. vision detector (section 3).
- **User confirmation** for side effects, and measuring how often a user would have to click.
- **Answer verification** against the source, aimed at the data-corruption attacks that got past
  almost every defense in the current study.

## 6. Evaluation improvements

- More runs per cell (temperature > 0, several seeds) to narrow the confidence intervals.
- A second agent model, local or hosted, to see which findings hold across models.
- A held-out attack set written by someone who did not build the defenses.
