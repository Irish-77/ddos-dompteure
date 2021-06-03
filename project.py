# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

########

# %% Imports
import numpy as np
import dask
import dask.dataframe as dd
from functions import is_public_ip
from sklearn.cluster import SpectralClustering

# %% Install Dataset

df = dd.read_csv("unbalaced_20_80_dataset.csv")

# %% Save metadata

shape = df.shape
columns = df.columns

# %% Print metadata

print("shape:", shape)
print("columns:", columns)
print("Label:", df["Label"].value_counts().compute())

# %% Analyze Data
src_ips = df["Src IP"].apply(is_public_ip)
des_ips = df["Dst IP"].apply(is_public_ip)

# %% Print Results

print("Source IP:\n", src_ips.value_counts())
print("Destination IP:\n", des_ips.value_counts())

# %% Remove Private IPs

df_clean = df[(src_ips == True)]

# %% Simple Clustering
n_80 = int(len(df)*(80/100))
df_clust_80 = df.select_dtypes(exclude = [object])[:n_80].dropna()
df_clust_20 = df.select_dtypes(exclude = [object])[n_80:].dropna()

sc = SpectralClustering(2, n_init=100, assign_labels='discretize')
sc.fit_predict(df_clust_80) 