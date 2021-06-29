from pathlib import Path
from joblib import dump, load
import numpy as np
import pandas as pd

class Classifier:

    current_ml_model = None
    models = {
        'NN': Path('models/neural_network_prod.model'),
        'RFC_Ada': Path('models/RandomForestClassifier_AdaBoost.joblib'),
        'RFC': Path('models/RandomForestClassifier.joblib')
    }
    
    blacklist = Path('blacklist.txt')

    def __init__(self, model_name='RFC'):
        self.set_current_model(model_name)
        
        f = open(self.blacklist, 'w')
        f.close()
        
    def set_current_model(self, model_name):
        self.current_ml_model = self.load_obj(self.models[model_name])
    
    def read_blacklist(self):
        file = open(self.blacklist, 'r')
        lines = file.read().split('\n')
        file.close()
        return lines
    
    def save_blacklist(self, lines):
        file = open(self.blacklist, 'w')
        file.write(lines)
        file.close()   
        
    def is_malicious(self, ip):
        ips = self.read_blacklist()
        if ip in ips:
            return True
        else:
            return False
    
    def predict(self, X, blacklist = True):
        X_transformed, ips = self.pipeline(X)
        
        predictions = self.current_ml_model.predict(X_transformed)
        
        ddos_ips = ips.iloc[np.where(predictions == 'ddos')].values
        
        ddos_ips = [item for sublist in ddos_ips for item in sublist]
        
        if blacklist:
            blacklist_ips = self.read_blacklist()
            for d in ddos_ips:
                if d not in blacklist_ips:
                    blacklist_ips.append(d)
            lines = '\n'.join(blacklist_ips)
            self.save_blacklist(lines)
        
        return predictions, ips
    
    def load_obj(self, filename):
        return load(filename)

    def encode_ports(self, x):
        if x < 1024:
             y= 'System'
        elif x > 1023 and x < 49152:
             y= 'User'
        else :
             y= 'Dynamic' 
        return y

    def pipeline(self, df):
        try:
            df = df.drop(['Unnamed: 0'], axis=1)
        except:
            pass
        try:
            df = df.drop(['Label'], axis=1)
        except:
            pass
        
        # Stage 1 - Cleaning
        df_cleaned = df[~df['Flow Byts/s'].isin([np.inf, -np.inf])]
        df_cleaned = df_cleaned.dropna(subset=['Flow Byts/s'])
        df_cleaned = df_cleaned.drop(['Fwd URG Flags', 'Bwd URG Flags', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Blk Rate Avg'], axis=1)
        
        # Stage 2 - Exploring
        df_cleaned['dst_port_transformed'] = df_cleaned['Dst Port'].apply(self.encode_ports)
        df_cleaned['src_port_transformed'] = df_cleaned['Src Port'].apply(self.encode_ports)
        to_be_removed = ['Fwd PSH Flags', 'Bwd PSH Flags', 'FIN Flag Cnt', 'URG Flag Cnt', 'Src Port', 'Dst Port', 'Flow ID', 'Timestamp']
        df_explored = df_cleaned.drop(to_be_removed, axis=1)        
        
        # Stage 3 - Preperation
        scaler = self.load_obj(Path('models/std_scaler.transformer'))
        pca = self.load_obj(Path('models/pca.transformer'))
        encoder = self.load_obj(Path('models/one_hot_encoder.transformer'))
        
        
        category_vars = ['Protocol','SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'dst_port_transformed', 'src_port_transformed']
        object_vars = ['Dst IP', 'Src IP']
        continuous_vars = df_explored.columns[~df_explored.columns.isin(category_vars) & ~df_explored.columns.isin(object_vars)]
        
        
        X = scaler.transform(df_explored[continuous_vars].values)
        principal_components = pca.transform(X)
        col_names = [f'PC-{i}' for i in range(principal_components.shape[1])]
        df_pca = pd.DataFrame(data = principal_components, columns = col_names)
        
        to_be_encoded = ['Protocol', 'dst_port_transformed', 'src_port_transformed']
        df_encoded = pd.DataFrame(encoder.transform(df_explored[to_be_encoded]))
        df_encoded.columns = encoder.get_feature_names(to_be_encoded)
        
        to_be_not_encoded = [i for i in category_vars if i not in to_be_encoded]
        
        max_pca = 24
        df_categories = pd.concat([df_encoded, df_explored[to_be_not_encoded].reset_index()[to_be_not_encoded]], axis = 1)
        df_prepared = pd.concat([df_categories, df_pca.iloc[:,list(range(max_pca))]], axis = 1)

        return df_prepared, df_explored[['Src IP']]
    
    def save_obj(self, obj, file):
        pass