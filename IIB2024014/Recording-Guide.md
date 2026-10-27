# OS Injection Lab - Recording Guide

Record a 2-3 minute demonstration of the in-band OS command injection project. Target duration: 2 minutes 50 seconds. Read only the quoted narration during the recording. The action instructions and beginner explanations are preparation, not spoken content.

## Understand these ideas first - do not record this section

| Term | Meaning in this project |
|---|---|
| OS | Operating system. The program runs inside a Linux Docker container. |
| Shell | A command interpreter. It reads command text and can treat symbols as instructions. |
| SHA-256 checksum | A fingerprint calculated from file contents. It is not encryption. You do not need to read out the long value. |
| OS command injection | User input changes an OS command the server executes. Here, an input intended as a filename adds another command. |
| Payload | The deliberately crafted input used to demonstrate the flaw. |
| In-band | The injected command's output returns in the same web response. |
| Mitigation | A change that prevents the vulnerable behavior. Here, replace the shell command with native Python hashing. |
| Allow-list | A small set of values that the server accepts. Here, three known sample filenames. |

The app's intended task is simply to hash a sample file. Its vulnerable path builds a shell command from the input. Its secure path hashes the file without a shell and checks that the filename is one of three allowed values. Both paths already exist; you do not edit code while recording or claim that toggling a display label applies the fix.

## Prepare before starting the recording

1. Open a terminal and run the following. The first line changes into the project directory; the second starts the lab.

```bash
# From the group repository root:
cd IIB2024014/os-injection-lab
docker compose up --build -d --wait
```

2. Open `http://127.0.0.1:8080` in the browser. If the page hangs during rehearsal, run `docker compose restart lab`, wait a few seconds, and reload it. Test that the buttons respond before recording.
3. Prepare these four tabs before recording:
   - A - [Running website](http://127.0.0.1:8080).
   - B - [Vulnerable source, lines 27-44](https://github.com/devanshrai23/CS_Lab4_Assignment/blob/main/IIB2024014/os-injection-lab/app/server.py#L27-L44).
   - C - [Secured source, lines 64-78](https://github.com/devanshrai23/CS_Lab4_Assignment/blob/main/IIB2024014/os-injection-lab/app/server.py#L64-L78).
   - D - [Ownership declaration](https://github.com/devanshrai23/CS_Lab4_Assignment/blob/main/IIB2024014/README.md#ownership).
   Use the browser tabs for source display, or use the same local source file in an editor if you prefer.
4. Put this guide on another device, on paper, or beside the recording area. Only the browser and editor need to be visible in the video. Increase editor text size until the code is readable.
5. In the browser, click **Normal filename** and reload if you want empty output cards for the opening. Do a complete practice run before the real take.
6. Open your screen recorder, for example OBS Studio. In **Sources**, click **+**, add a screen/display capture source, and select the display containing your browser and editor. On Wayland the source may be labelled **Screen Capture (PipeWire)**. Confirm that your desktop is visible in the preview.
7. Speak and check that the microphone meter moves in the Audio Mixer. If it does not, choose your microphone in **Settings > Audio**. Click **Start Recording**, speak for ten seconds, then **Stop Recording**. Play the test file and check both speech and text readability. OBS's **File > Show Recordings** can help locate saved recordings. Use the existing working recorder if you already have one set up.
8. Start the real take, minimise OBS, and return to the browser. Read only the quoted paragraphs below. Move your pointer to the item being discussed; do not read the action instructions aloud.

Recording setup reference: [OBS quick-start guide](https://obsproject.com/kb/quick-start-guide).

## Screen 1 - Browser introduction - 0:00-0:20

**Show and do:** Show the app at its top, with the title and your identity in the sidebar. Do not run a request yet.

**Say:**

> Hello, I am Manas Singh, roll number IIB2024014. My assigned category is OS command injection, using the in-band variant. This means an injected command runs on the server and its output returns in the same web response.

**Your checkpoint:** The viewer knows your identity, category and chosen variant.

## Screen 2 - Normal behavior - 0:20-0:40

**Show and do:** Click **Normal filename**. Check that the input is `welcome.txt`. Click **Run comparison**. Scroll enough to show the input and both output cards. Point at the matching long values; do not read the hash aloud.

**Say:**

> This tool calculates a file's SHA-256 checksum, which is a fingerprint of its contents. With welcome dot txt as normal input, both implementations return the same fingerprint. So both versions perform the intended task.

**Expected result:** Left: `200 - EXECUTED`. Right: `200 - ACCEPTED`. Both show the same checksum for `welcome.txt`. The visual separator in the app may appear as a dot rather than a hyphen.

## Screen 3 - Vulnerable source and root cause - 0:40-1:05

**Show and do:** Switch to tab B, the vulnerable source. Keep lines 27-44 visible. Point first to line 30 and then line 33. The two important statements are:

```python
command = f"{SHA256SUM} -- {filename}"
```

```python
shell=True,
```

**Say:**

> Here, the filename is inserted into a command string. Popen starts a process, and shell equals True tells a shell to interpret that string. This is the root cause: user input can become executable instructions instead of remaining a filename.

**For your understanding:** `{filename}` inserts what the user typed. `Popen` starts the command; `shell=True` asks a shell to interpret it. `stdout=subprocess.PIPE` and `communicate()` capture the output so the application can return it. The flaw is the combination of untrusted text and shell interpretation, not all uses of Popen.

## Screen 4 - Exact working exploit - 1:05-1:35

**Show and do:** Return to the browser. Click **Injection payload**. Check that the input is exactly:

```text
welcome.txt; printf 'OS_INJECTION_CONFIRMED\n'
```

Point at the semicolon, then click **Run comparison**. Point at `OS_INJECTION_CONFIRMED` in the left output. The right side will also update; explain it in the next scene.

**Say:**

> My payload contains a valid filename, a semicolon, and printf. The semicolon separates commands; printf prints this harmless marker. I run the comparison. On the vulnerable side, the server returns OS underscore INJECTION underscore CONFIRMED after the checksum. That proves the extra command executed. Because I can read its output directly, this is in-band injection.

**Expected result:** The vulnerable card shows `200 - INJECTION CONFIRMED`; the marker appears on a separate line after the checksum. The server actually executes printf. It is not a frontend-generated fake result. Use the preset button so quotes and the backslash are copied correctly.

## Screen 5 - Implemented mitigation and same blocked payload - 1:35-2:10

**Show and do:** In tab A, leave the payload unchanged. First point to the right card: `422 - BLOCKED` and `Unknown sample filename.` Switch to tab C, the secured source. Point to line 67, `if filename not in ALLOWED_FILES`, and line 74, `hashlib.sha256(...)`. Return to tab A so both outputs are visible for the last sentence.

**Say:**

> The secured function uses hashlib to calculate the checksum directly in Python. It never starts a shell. It also accepts only three allowed filenames. The identical payload returns 422, blocked, with no command output. This validation rejects the payload; removing shell execution is the primary fix.

**For your understanding:** The allow-list rejects this specific input before hashing. Independently, the fixed function has no shell execution path. Do not claim that HTTP 422 itself provides security; it is the response reporting that the server rejected the filename. Both implementations are already present in the code.

**Evidence action:** Pause briefly with both results visible. The existing `evidence/03-comparison-detail.jpg` supplies the required blocked-attempt screenshot. If you change the project, capture fresh evidence during rehearsal. Do not include screenshot-save dialogs in the video.

## Screen 6 - Other mitigation options, theory - 2:10-2:35

**Show and do:** In tab A, click **03 Defense notes** in the left sidebar, or scroll to **Other defenses to explain**. Point to the argument-vector, allow-list and least-privilege notes in order. No new payload is needed.

**Say:**

> If an external program is required, use a fixed executable and an argument list with shell equals False, plus server-side allow-list validation. Least privilege means running with limited permissions. It reduces potential damage but does not fix unsafe command construction.

**For your understanding:** An argument list separates the program name from its input values, without asking a shell to parse them. Still validate arguments and prevent dangerous options. Least privilege limits what the process can access if a flaw remains. Native hashing avoids the shell and is the primary mitigation already demonstrated. These options match the categories in the PDF; the lecture slides were not supplied, so compare the wording with your own slides.

## Screen 7 - Ownership and finish - 2:35-2:50

**Show and do:** Switch to tab D, the ownership declaration on GitHub. Keep the row with Manas Singh, IIB2024014, OS command injection, and the in-band variant visible.

**Say:**

> The repository's ownership table identifies my category and variant. The demonstration shows the vulnerable code, working payload, root cause, implemented fix, and the same payload failing. Thank you.

Stop the recording. The source and ownership declaration are available in the shared group repository under IIB2024014.

## Check the recording before submitting

- Play it once. Confirm that your voice, code, exact payload and both output cards are readable/audible.
- Aim for 2:40-3:00. Rehearse with a timer; the timestamps are targets, not a reason to rush. Trim pauses before removing a required explanation.
- Keep the blocked-attempt screenshot in the repository's evidence folder.
- The source, ownership declaration and evidence are included in the public group repository under IIB2024014. Confirm your group's other members have completed their categories.
- Submit the group video or permitted unlisted link, and the repository link, using the course's instructions. Check link access before submission.
- Stop the local lab after you finish with `docker compose down` from the project directory.

## Answers to learn before the viva

| Question | Answer |
|---|---|
| Why is this an injection? | Input intended as a filename introduces another shell instruction. |
| Why in-band? | The marker returns in the same web response. |
| What does the semicolon do? | It separates shell commands. |
| Why printf? | It proves command execution by printing a harmless fixed marker. |
| What is the root cause? | Untrusted text is inserted into a command evaluated by a shell. |
| What is the primary fix? | Compute the checksum using hashlib, without a shell or OS command. |
| What else was implemented? | An exact allow-list of the three sample filenames. |
| Does -- stop the exploit? | No. It ends the utility's option parsing, but the shell still interprets the semicolon. |
| Does least privilege remove injection? | No. It reduces impact if exploitation occurs. |
| Are the milliseconds the proof? | No. This is in-band; the returned marker is the proof. |

Learn what the lines mean and adapt your presentation honestly under the assignment's originality rules. The spoken script identifies your assigned category without claiming that reading a prepared script demonstrates personal authorship.

## Requirement mapping and references

| Assignment point | Video scene |
|---|---|
| (a) Vulnerable implementation | Screen 3 |
| (b) Exact working payload | Screen 4 |
| (c) Root cause | Screen 3 |
| (d) Implemented mitigation, same payload fails, screenshot | Screen 5 and evidence folder |
| (e) Theory of alternatives | Screen 6 |
| Individual identity and ownership | Screens 1 and 7 |

Source assignment: `Assignment_Web_Server_Security.docx.pdf`, especially Table 2 and Deliverables. The source repository and student's own voice-over video are separate required deliverables.

Technical references: [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations), [OWASP command injection defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).
