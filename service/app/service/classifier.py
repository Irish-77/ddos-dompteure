from joblib import dump, load
from operator import add
import pandas as pd
import numpy as np

class Classifier:
    models = {
        'neural_network': './app/service/models/neural_network.model',
        'random_forest_classifier_adaboost': './app/service/models/random_forest_classifier_adaboost.model'
    }
    prediction_mapping = {
        0: 'ddos',
        1: 'benign'
    }
    scaler = None
    pca = None
    encoder = None

    def __init__(self, model_name = None):
        self.current_ml_model = None
        self.scaler = self._load_obj('./app/service/models/std_scaler.transformer')
        self.pca = self._load_obj('./app/service/models/pca.transformer')
        self.encoder = self._load_obj('./app/service/models/one_hot_encoder.transformer')

        try:
            self.set_current_model(model_name)
        except:
            self.set_current_model(next(iter(self.models.keys())))

    def set_current_model(self, model_name):
        self.current_ml_model = self._load_obj(self.models[model_name])

    def predict(self, X):
        X_transformed = self.pipeline(X)
        predictions = self.current_ml_model.predict(X_transformed)        
        return predictions

    def voting(self, X):
        X_transformed = self.pipeline(X)

        n = len(self.models.keys())
        cumulated_votings = [0]*len(X_transformed)
        for model in iter(self.models.keys()):
            self.set_current_model(model)
            new_votings = self.current_ml_model.predict_proba(X_transformed)
            cumulated_votings = [cumulated_votings[i]+new_votings[i][0] for i in range(len(new_votings))]

        votings = []
        for i in cumulated_votings:
            if i/n < 0.5:
                votings.append(self.prediction_mapping[0])
            else:
                votings.append(self.prediction_mapping[1])
        return votings

    def pipeline(self, df):
        try:
            df = df.drop(["Unnamed: 0"], axis=1)
        except:
            pass
        
        # Stage 1 - Cleaning
        df_cleaned = df[~df['Flow Byts/s'].isin([np.inf, -np.inf])]
        df_cleaned = df_cleaned.dropna(subset=['Flow Byts/s'])
        df_cleaned = df_cleaned.drop(['Fwd URG Flags', 'Bwd URG Flags', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Blk Rate Avg'], axis=1)

        # Stage 2 - Exploring
        df_cleaned['dst_port_transformed'] = df_cleaned['Dst Port'].apply(self._encode_ports)
        df_cleaned['src_port_transformed'] = df_cleaned['Src Port'].apply(self._encode_ports)
        to_be_removed = ['Fwd PSH Flags', 'Bwd PSH Flags', 'FIN Flag Cnt', 'URG Flag Cnt', 'Src Port', 'Dst Port', 'Flow ID', 'Timestamp']
        df_explored = df_cleaned.drop(to_be_removed, axis=1)        
        
        # Stage 3 - Preperation      
        category_vars = ['Protocol','SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'dst_port_transformed', 'src_port_transformed']
        object_vars = ['Dst IP', 'Src IP']
        continuous_vars = df_explored.columns[~df_explored.columns.isin(category_vars) & ~df_explored.columns.isin(object_vars)]
        
        X = self.scaler.transform(df_explored[continuous_vars].values)
        principal_components = self.pca.transform(X)
        col_names = [f'PC-{i}' for i in range(principal_components.shape[1])]
        df_pca = pd.DataFrame(data = principal_components, columns = col_names)
        
        to_be_encoded = ["Protocol", "dst_port_transformed", "src_port_transformed"]
        df_encoded = pd.DataFrame(self.encoder.transform(df_explored[to_be_encoded]))
        df_encoded.columns = self.encoder.get_feature_names(to_be_encoded)
        
        to_be_not_encoded = [i for i in category_vars if i not in to_be_encoded]
        
        max_pca = 24
        df_categories = pd.concat([df_encoded, df_explored[to_be_not_encoded].reset_index()[to_be_not_encoded]], axis = 1)
        df_prepared = pd.concat([df_categories, df_pca.iloc[:,list(range(max_pca))]], axis = 1)
   
        return df_prepared

    def _load_obj(self, filename):
        return load(filename)
        
    def _encode_ports(self, x):
        if x < 1024:
             y= 'System'
        elif x > 1023 and x < 49152:
             y= 'User'
        else :
             y= 'Dynamic' 
        return y