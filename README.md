# DDoS Dompteure

## Your Acts for the Night
- Bastian "The Fearless Ringmaster" Berle
- Ferdinand "Lion Tamer" Muth
- Jonas "Lady Cannonball" Wuttke
- Ron "The Strange Clown" Holzapfel


## Motivation and Goal
Distributed denial of service attacks are an increasing problem for network security and availability. To avoid these availability shortages, it is necessary for companies to implement preventive systems. We try to help companies by implementing a machine learning algorithm to classify aggregated network communication data. For that, we use a dataset which consists of data of multiple sources. See the links below for more information. Since the data is generated, differences to a real world application can be expected.

**Dataset origin:** https://www.kaggle.com/devendra416/ddos-datasets \
**Feature descriptions:** https://www.unb.ca/cic/datasets/ids-2018.html \
**Dataset generation:** https://www.ijcseonline.org/pdf_paper_view.php?paper_id=4011&28-IJCSE-06600.pdf

We extended the models by embedding them inside an api and connecting them to a database. The proposed application of the models can used by firewalls to extend their security measures and filter ip addresses which are suspicious.

## Installation
We recommend to install Python version 3.9.1 for optimal use of the project. Furthermore, jupyter is required to run the notebooks. You can install it using `pip install jupyter`. Moreover, please install all packages using `pip install -r requirements.txt` inside this folder. For an easy introduction to the project, please have a look at the starter.ipynb.

For our service implementation, please install docker and run `docker compose up` inside the service folder.

## Files and Folders

**Folders**:

| Folder                         | Content                                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| img                            | images created during the execution of the notebooks                                                                 |
| models                         | trained models and fitted transformation objects (e.g. pca , std_scaler, one_hot_encoder)                            |
| scripts                        | scripts which contain a compressed form of some of our code                                                          |
| service                        | code for the ddos implementation as a docker container (requires changes to run this without docker containers)      |

**Files**:
| File                           | Content                                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| starter.ipynb                  | introduction to the project and how to use it                                                                        |
| data_cleaning.ipynb            | cleaning of anomalies inside the data                                                                                |
| data_exploration.ipynb         | visualizations and insights about the data                                                                           |
| data_preparation.ipynb         | transforming the data                                                                                                |
| data_modeling.ipynb            | test implementation of the classifier script                                                                         |
| model_*.ipynb                  | training, testing of models                                                                                          |


## Sources
- [CSE-CIC-IDS2018](https://registry.opendata.aws/cse-cic-ids2018/)