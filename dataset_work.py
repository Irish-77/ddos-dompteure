import numpy as np
import pandas as pd
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
import dask
import dask.dataframe as dd
import dask.array as da
df = dd.read_csv('unbalaced_20_80_dataset.csv')


#data-cleaning code
df_inf = df[~da.isinf(df['Flow Byts/s'])]
df_nonull = df_inf.dropna(subset=['Flow Byts/s'])
df = df_nonull.drop(['Fwd URG Flags', 'Bwd URG Flags', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Blk Rate Avg'], axis=1)


#data-exploration code
# allocating columns
category_vars = ['Label', 'Protocol', 'Fwd PSH Flags', 'Bwd PSH Flags', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'dst_port_transformed', 'src_port_transformed']
object_vars = ['Dst IP', 'Flow ID', 'Src IP', 'Timestamp'] #df.select_dtypes(include=['object']).columns
continuous_vars = df.columns[~df.columns.isin(category_vars) & ~df.columns.isin(object_vars)]

def f(x):
    if x < 1024:
         y= 'System'
    elif x > 1023 and x < 49152:
         y= 'User'
    else :
         y= 'Dynamic' 
    return y

df['dst_port_transformed'] = df['Dst Port'].apply(f,meta=('Dst Port', 'object'))
df['src_port_transformed'] = df['Src Port'].apply(f,meta=('Src Port', 'object'))

to_be_removed = ['Fwd PSH Flags', 'Bwd PSH Flags', 'FIN Flag Cnt', 'URG Flag Cnt', 'Src Port', 'Dst Port', 'Flow ID', 'Unnamed: 0', 'Timestamp']

df = df.drop(to_be_removed, axis=1)

#data-prep code
# allocating columns
category_vars_no_order = ['Label', 'Protocol','SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'dst_port_transformed', 'src_port_transformed']
category_vars = [i for i in df.columns if i in category_vars_no_order]

object_vars = ['Dst IP', 'Src IP'] #df.select_dtypes(include=['object']).columns
continuous_vars = df.columns[~df.columns.isin(category_vars) & ~df.columns.isin(object_vars)]

#PCA
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
x = StandardScaler().fit_transform(df[continuous_vars].values)
pca = PCA(n_components='mle')
principalComponents = pca.fit_transform(x)
# rename columns with PC-{#component}
col_names = []
for i in range(principalComponents.shape[1]):
    col_names.append(f'PC-{i}')
principalDf = pd.DataFrame(data = principalComponents, columns = col_names)
df_label = df['Label'].compute()
# add label to PCs
df_pca = pd.concat([principalDf, df_label.reset_index()['Label']], axis = 1)


#One-Hot-Encoding
from sklearn.preprocessing import OneHotEncoder
to_be_encoded = ["Protocol", "dst_port_transformed", "src_port_transformed"]
to_be_not_encoded = [i for i in category_vars if (i not in to_be_encoded and i != "Label")]
df_computed = df[category_vars].compute()
encoder = OneHotEncoder(sparse=False)
df_encoded = pd.DataFrame(encoder.fit_transform(df_computed[to_be_encoded]))
df_encoded.columns = encoder.get_feature_names(to_be_encoded)
df_categories = pd.concat([df_encoded, df_computed[to_be_not_encoded].reset_index()[to_be_not_encoded]], axis = 1)


df_prepared = pd.concat([df_categories, df_pca.iloc[:,list(range(24)) + [-1]]], axis = 1)
df_prepared.to_csv("prepared_ds.csv")

