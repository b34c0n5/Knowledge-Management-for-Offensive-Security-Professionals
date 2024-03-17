---
Topics:
  - "[[01 - Pentesting]]"
  - "[[01 - Networking]]"
  - "[[01 - Programming]]"
  - "[[01 - Red Team]]"
Types:
  - "[[02 - Documentation]]"
tags:
  - course
  - project
date created: 
date modified:
---


# Note Taking for Hackers

## Preface

Hello, my name is [Rafael Pimentel](https://www.linkedin.com/in/rafa-pimentel/), and I'm a cybersecurity student. I saw the necessity to make this course because of a general lack of orientation towards taking notes and managing your knowledge in a hacking context.

Before diving into offensive security, I explored various disciplines, including bodyweight fitness, nutrition, and music production. Starting each journey independently, I became proficient in these areas. However, a recurring challenge was my failure to maintain comprehensive notes to keep track of my knowledge. Despite retaining crucial details, *much of the knowledge I acquired faded over time*.

My transition to cybersecurity began in mid-2022, moving from music production with no prior experience. Under the mentorship of my brother, [Robert Pimentel](https://www.linkedin.com/in/pimentelrobert1), we designed a path to success in this new field. My certification journey started with the eJPT (INE) to introduce me to the basics, followed by the OSCP (Offsec) to prepare for HR interviews. I then delved into Active Directory with CRTO and CRTE (Altered Security) and aimed to complete the OSEP (Offsec) as the culmination of my short-term certification goals. After achieving these milestones, I planned to start my studies at WGU, a college renowned for its IT programs.

Embracing this new challenge was exciting for me. Determined not to repeat past mistakes, I sought a *reliable method to document my newly acquired knowledge*. That's when Obsidian caught my attention, recommended, and mentioned by various offensive security professionals I respect. I decided to give it a shot and have been using it ever since.

This course is designed to provide you with knowledge management systems in a straightforward and efficient way. While my focus is on ethical hacking, the principles and strategies shared here will benefit anyone pursuing a college degree or a challenging certification.

## 1. Introduction to Obsidian

I prefer using Obsidian[^1] for notetaking because of its *flexibility*. The ability to customize the user interface, functionality, and workflows is crucial when spending countless hours studying and taking notes on a computer. Obsidian excels in offering these options with ease.

You can install Obsidian on various platforms, including Mac, Windows, Linux, and mobile devices. While iPhone users need Obsidian Sync, Android users can access it for free.

For those unfamiliar with Obsidian, I highly recommend spending some time with the official documentation[^2]. The creators have done an exceptional job in explaining the application's functionality. Initially, I considered explaining the installation process and basic features myself, but I realized it would only duplicate the excellent information already available.

Moving forward, I'll assume you've read the documentation and are familiar with basic navigation within the app.

### 1.1. My Note-Taking Strategy

How I approach notetaking is by *prioritizing simplicity, scalability, and automation*. This is achieved by following different practices:

- Keeping a *comprehensive folder structure* throughout the vault
- Keeping a *general note structure*
- Categorizing notes in *few categories* as possible
- The use of *custom templates* for note creation

If you already know Zettelkasten[^3], you will know that the use of categories at all is highly discouraged[^4] however I recommend you *stick to whatever methodology feels more natural to yourself* and avoid rules that kill your productivity.

> Because of how vast my vault has come to be, at some point I ditched the idea of not using categories and made a compromise of using only four categories. This is because of the inherent difference between particularly different topics such as "programming" and "pentesting" notes for example.

## 2. Getting to Know the Vault

In my *note-organizing system*, I use a structured approach with folders to manage categorization effectively:

### 2.1. Organizational Folders

First, we have **Organizational Folders**:

1. **01 - Topics:** This folder is designated for *major categories/topics* that are pertinent to my field of work, such as "pentesting," "red team," "programming," and "networking." These categories broadly *define the subjects of all notes in my vault*. For quick recognition, notes within this folder start with the prefix `01 -`.

![[Pasted image 20240317120621.png]]

2. **02 - Types:** This folder is organized by the *nature or purpose of the content*, including classifications like "cheat sheets," "documentation," "techniques," and "write-ups." This categorization not only aids in *distinguishing between different types of notes* but also in *choosing the appropriate template for each*, ensuring consistency. Notes here are marked with a `02 -` prefix, reflecting their organizational function.

![[Pasted image 20240317120632.png]]

### 2.2. Content Folder
The main bulk of my notes resides in the **Content Folder**:

- **03 - Content:** This folder contains all the types of notes mentioned above and is where most of the work happens. Here, the naming convention for notes is more flexible.

While the Zettelkasten method typically advises against folder hierarchies, I find that a single folder for each note type aids significantly in manual searches for specific notes (e.g., finding a *cheat sheet* on Active Directory without sifting through unrelated documentation).

> Additionally, I maintain a *temporary folder* within the contents folder for current certification materials, streamlining study and review. Once the certification/course is completed, I move these notes into their respective folders.

![[Pasted image 20240317120609.png]]

### 2.3. Tasks Folder

As proficiency grows, so does the number of tasks, ideas, and to-dos. To keep track of these, I've dedicated a **Tasks Folder**:

- **04 - Tasks:** This folder includes *Kanban cards*[^5], a methodological tool used by development teams for *workflow management*. These cards are useful for listing tasks that advance you toward your goals. The naming convention here is also flexible.

> I also added "Canvas Notes"[^6] within this folder for capturing sudden but brilliant ideas, ensuring they're not forgotten and complex diagrams.

![[Pasted image 20240317120805.png]]

### 2.4. Templates Folder

One reason I'm particularly fond of Obsidian is its *support for extensive plugins, customization options, and the ability to create personal templates*. To manage special template notes I use the **Templates Folder**:

- **04 - Templates:** Serves as a *container for various templates*, used to automate the process of creating a new note. These templates are prefaced with numbers.

Contained within this folder is a *templater script*[^7] ("Note Generator") activated upon creating a note, which facilitates the selection of the necessary structure, greatly enhancing productivity by eliminating decision-making for each new note.

![[Pasted image 20240317120854.png]]

This folder also includes a *sub-folder* with *basic structural elements* common across different notes, utilized by the Note Generator script, following a sequential numbering system for easy reference.

![[Pasted image 20240317121156.png]]

This customized structure accommodates my workflow, emphasizing efficiency and organization, and *can be modified to fit different individual preferences*.

### 2.5. Attachments Folder

Whenever a screenshot or media file is added to my vault, it's automatically stored in the **Attachments Folder**:

- **Attachments**: This folder *consolidates all media and attachments* in one location. You can set this folder as the default location for media storage by selecting it in the settings menu under *Files and Links*.

### 2.6. Miscellaneous Folders

While we've covered the essential folders necessary for your vault's functionality, *there's room for additional, optional folders based on your personal needs or preferences*. These folders can be tailored to accommodate any specific requirements or extra documents you wish to include, providing further customization and flexibility in managing your knowledge resources.

This organizational system is tailored to my preferences and has proven scalable and intuitive for my note-taking process. However, you should *adopt or adapt the organizational strategy to best suits your needs*.

## 3. Note Types

As previously discussed, the structured approach to notetaking encompasses *four distinct types of notes*:

- Cheatsheets
- Documentation
- Techniques
- Write-Ups.

Each type has a tailored layout to facilitate efficiency and organization. Below is a brief exploration of each note type and the role of the note generator script in creating new notes.

### 3.1. Cheatsheet Notes

**Cheatsheet notes** are practical and concise, primarily containing commands and brief instructions to execute various tasks. These notes are designed for *quick reference*, *avoiding the use of detailed theoretical explanations*. They can be personal compilations or adaptations from resources found online, such as a "Windows Privilege Escalation Cheatsheet".

### 3.2. Documentation Notes

**Documentation notes** are *comprehensive records* that include tool documentation, theoretical concepts (like understanding what Active Directory is), and programming languages' syntax and usage. These notes serve as a knowledge base, offering *in-depth explanations and details*.

### 3.3. Techniques Notes

**"Technique notes"** document *specific methodologies* related to penetration testing, red team, or purple team operations. They are structured to include a dedicated MITRE classification table and detailed steps for reproduction, among other critical sections. These notes are invaluable for methodical practice and training.

> If you're a security professional working in a different area than mine, I recommend customizing the "Technique Note" template to include a classification table that suits your specific requirements.

### 3.4. Write-Ups Notes

**Write-ups notes** document the *process and findings from hacking activities*, such as CTFs and exams.

### 3.5. Naming Convention

When it comes to naming notes, *practices vary widely*. Some people prefer to start their note names with the date[^8], while others adopt a more relaxed approach[^9]; I fall into the second group.

For organizing folders, however, I prefer to prefix their names with a number for better organization and accessibility. As for naming individual notes, I generally don't adhere to a strict convention, with a few exceptions. Specifically, for *topics*, *types*, and *templates* (which I'll discuss in the following section), I do use a prefix before the note name. This helps in *quickly identifying these as special notes* with specific purposes.

# References

[^1]: [Download - Obsidian](https://obsidian.md/download)
[^2]: [Home - Obsidian Help](https://help.obsidian.md/Home)
[^3]: [Why Categories for Your Note Archive are a Bad Idea • Zettelkasten Method](https://zettelkasten.de/posts/no-categories/)
[^4]: [Getting Started • Zettelkasten Method](https://zettelkasten.de/overview/)
[^5]: [Kanban - A brief introduction | Atlassian](https://www.atlassian.com/agile/kanban)
[^6]: [Obsidian Canvas - Visualize your ideas](https://obsidian.md/canvas)
[^7]: [Practically Paperless with Obsidian, Episode 6: Tips for Naming Notes – Jamie Todd Rubin](https://jamierubin.net/2021/11/09/practically-paperless-with-obsidian-episode-6-tips-for-naming-notes/)
[^8]: [Introduction - Templater](https://silentvoid13.github.io/Templater/introduction.html)
[^9]: [Importance of naming with zettelkasten IDs? - Knowledge management - Obsidian Forum](https://forum.obsidian.md/t/importance-of-naming-with-zettelkasten-ids/16140)