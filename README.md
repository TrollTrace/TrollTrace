[![](https://visitcount.itsvg.in/api?id=TrollTrace&label=Profile%20Views&color=0&icon=7&pretty=false)](https://visitcount.itsvg.in)
# TrollTrace

![designer__3__720](https://github.com/TrollTrace/TrollTrace/assets/158124623/04e2fb83-68e1-40d2-9570-c94f9bfa6e39)

## Troll Trace Mission
Born out of a desire to aggressively defend business owners' right to do business without criminal interference, our mission is to protect our partner companies' digital infrastructure and sensitive information from all cyber threats. By engaging in continuous monitoring, thorough vulnerability assessments, and implementing advanced security measures, we strive to maintain our data assets' integrity, confidentiality, and availability. Additionally, we are committed to promoting a culture of cybersecurity awareness and resilience.

Table of Contents
=================
<!--ts-->
  * [Project Overview](#project-overview)
  * [Team Members](#team-members)
  * [Project Challenges](#project-challenges)
  * [Team Agreemeent](#team-agreement)
  * [System Selection](#systems-and-components-selection)
  * [Standard Operating Procedure](#standard-operating-procedure)
  * [Topologies/Cloud Architecture Design](#topologiescloud-architecture-design)
  * [Project Management Tool](#project-management-tool)
  * [Presentation Link](#presentation-link)
<!--te-->

## Project Overview
Troll Trace, a top-notch cybersecurity firm, has been hired to perform a threat emulation exercise for SimCorp, a prominent financial services provider. During this task, Troll Trace’s blue team will take on an active threat-hunting role.  The team will monitor and record adversarial activities inside SimCorp's Virtual Private Cloud (VPC).  This VPC will be treated as though it were a honeypot, and the blue team will observe without interfering in the adversaries' movement through the network. Blue team's objective is to rapidly uncover and rectify any gaps in detection capabilities to ensure all threats are detected.  The blue team must enhance detection systems quickly while preserving the integrity of the engagement. Strategic teamwork is crucial in protecting SimCorp's systems from cyber threats.

## Team Members
Meet the team behind TrollTrace:
* Steve Cherewaty [Github](https://github.com/SCherewaty) ! [LinkedIn](https://www.linkedin.com/in/steve-cherewaty-jr-b8727135/)
* Omar Ardid [Github](https://github.com/oardid) ! [LinkedIn](https://www.linkedin.com/in/ardidomar/)
* Gilbert Collado [Github](https://github.com/JapanesePlatano) ! [LinkedIn](https://www.linkedin.com/in/gilbert-collado-545099254)
  
![giphy](https://github.com/TrollTrace/TrollTrace/assets/158124623/012623e4-3807-4c94-bf51-e9018205f19f)

## Team Agreement
You can view our Team Agreement [here](/Documents/BLUETeamAgreement.pdf). This agreement outlines communication, collaboration, decision-making processes, and conflict-resolution guidelines within the team.

## System Selection
We selected the technology stack for Interslice based on the following criteria:
- **Scalability**: Choose scalable frameworks and tools to accommodate future growth and user demands.
- **Performance**: Prioritized technologies are known for their efficiency and speed to ensure optimal system performance.
- **Ease of Use**: Selected user-friendly tools to facilitate development and maintenance processes.
- **Community Support**: Preferred technologies with active developer communities for ongoing support and updates.

* IAM - Management of AWS resources access & permissions
* VPC - Amazon Virtual Private Cloud within which EC2 instances operate.
* VPC Flow Logs - Monitors IP traffic in and out of the VPC.
* CloudWatch - Within AWS, takes in VPC Flow Logs and organizes events.
* EC2 - Virtual machines within the VPC, acting as operating endpoints.
* Python - Automated tools used by Troll Trace are developed in Python.
* Splunk - Platform for searching mass log data.

View the full System Selection [here](/Documents/Systems%20Selection.pdf)

## Standard Operating Procedure
We follow a set of Standard Operating Procedures (SOPs) to maintain consistency and efficiency within the project:

* [Adversarial Activity Observation](/Documents/Adversarial%20Activity%20Observation.pdf)
* [Implementing Detective Controls on the Web Server](/Documents/Implementing%20Detective%20Controls%20on%20the%20Web%20Server.pdf)
* [STRIDE Analysis](/Documents/STRIDE%20Analysis.pdf)
  
## Topologies/Cloud Architecture Design
Here are some visual representations of TrollTrace's architecture and topology:

## Project Management Tool
We use [Github Projects](https://github.com/orgs/TrollTrace/projects/4) to track our progress and tasks. In Trello, we organize tasks into boards, lists, and cards, representing different stages of development. Each card contains a task description, assignee, due date, and checklist items.

## Presentation Link
View our live project presentation [here](https://zoom.us/rec/share/IqXSoEr6s8Z_CGJm9AKgRyS5NdZZZ1vl62I5Ilk53hCf0gIXGVgaJx4M3AxUOV2a.V5Rw0TFk7jA_1_Qb) for an overview of TrollTrace's features and functionalities.<br>
Take a view of our project presentation slideshow [here](https://docs.google.com/presentation/d/1IbE663TXz0m44mWh8pr4iv7RIKwPSGsE6LalXINAJnc/edit?usp=sharing)
