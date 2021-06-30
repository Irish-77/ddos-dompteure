from ipaddress import ip_address
from app.model.ip_entry import IPEntry
from app.model.ip_log import IPLog
from .classifier import Classifier
import pandas as pd
from app import db
from datetime import datetime
from sqlalchemy import func, distinct
from flask import abort

POSITIVE_LIST = 'whitelist'
NEGATIVE_LIST = 'blacklist'
POSITIVE_CLASSIFICATION = 'benign'
NEGATIVE_CLASSIFICATION = 'ddos'

classifier = Classifier()

def classify(X):
    classification = classifier.voting(X)
    return classification

def is_ddos(ip_list):
    ip_status = classify(ip_list)
    classified = [ip == NEGATIVE_CLASSIFICATION for ip in ip_status]
    return classified

def is_benign(ip_list):
    ip_status = classify(ip_list)
    classified = [ip == POSITIVE_CLASSIFICATION for ip in ip_status]
    return classified

def ip_status(ip):
    _check_ipv4_err(ip)
    entry = IPEntry.query.filter_by(ip=ip).first()
    if entry:
        return entry.status
    else:
        abort(404, 'IP Not Found')

def get_whitelist():
    return IPEntry.query.filter_by(status='whitelist').all()

def get_blacklist():
    return IPEntry.query.filter_by(status='blacklist').all()

def get_from_log_by_ip(ip, limit=10):
    _check_ipv4_err(ip)
    logs = IPLog.query.filter_by(src_ip=ip).order_by(IPLog.entry_date.desc()).limit(limit).all()
    if logs:
        positives = len([log for log in logs if log.classification == POSITIVE_CLASSIFICATION])
        negatives = limit - positives
        counts = {POSITIVE_CLASSIFICATION: positives, NEGATIVE_CLASSIFICATION: negatives}
        return counts
    else:
        abort(404, 'IP Not Found')

def new_ip(data):
    classifications = classify(data)
    for i in range(len(classifications)):
        a, b = update_ip_entry(data.iloc[i, :], classifications[i])
        db.session.add_all([a, b])
    db.session.commit()
    return classifications

def update_ip_entry(data, classification):
    ip = data['Src IP']
    _check_ipv4_err(ip)
    _check_ipv4_err(data['Dst IP'])
    status = _get_status_from_classification(classification)

    current_entry = IPEntry.query.filter_by(ip=ip).first()
    if  current_entry != None:
        current_entry.status = status
    else:
        current_entry = IPEntry(ip=ip, status=status)

    log_entry = _create_log_entry_from_df(data, current_entry, classification)

    return current_entry, log_entry
    # db.session.add(current_entry)
    # db.session.add(log_entry)
    # db.session.commit()

def _is_valid_classification(classification):
    try:
        _get_status_from_classification(classification)
        return True
    except:
        return False

def _get_status_from_classification(classification):
    if (classification == POSITIVE_CLASSIFICATION):
        status = POSITIVE_LIST
    elif (classification == NEGATIVE_CLASSIFICATION):
        status = NEGATIVE_LIST
    else:
        raise Exception('Unknown Classification')
    return status

def _check_ipv4_err(ip):
    if (_check_ipv4(ip) == False):
        print('Asd')
        abort(400, 'Invalid IP')

def _check_ipv4(ip):
    try:
        address = ip_address(ip)
        if address.version == 4:
            return True
        else:
            return False
    except:
        return False

def _create_log_entry_from_df(df, ip_entry, classification):
    try:
        try:
            timestamp = datetime.strptime(df['Timestamp'], '%d/%m/%Y %I:%M:%S %p')
        except:
            timestamp = datetime.strptime(df['Timestamp'], '%d/%m/%Y %I:%M:%S')
        return IPLog(
            classification = classification,
            ip_entry = ip_entry,
            flow_id = df['Flow ID'],
            src_ip = df['Src IP'],
            src_port = df['Src Port'].item(),
            dst_ip = df['Dst IP'],
            dst_port = df['Dst Port'].item(),
            protocol = df['Protocol'].item(),
            timestamp = timestamp,
            flow_duration = df['Flow Duration'].item(),
            tot_fwd_pkts = df['Tot Fwd Pkts'].item(),
            tot_bwd_pkts = df['Tot Bwd Pkts'].item(),
            tot_len_fwd_pkts = df['TotLen Fwd Pkts'].item(),
            tot_len_bwd_pkts = df['TotLen Bwd Pkts'].item(),
            fwd_pkt_len_max = df['Fwd Pkt Len Max'].item(),
            fwd_pkt_len_min = df['Fwd Pkt Len Min'].item(),
            fwd_pkt_len_mean = df['Fwd Pkt Len Mean'].item(),
            fwd_pkt_len_std = df['Fwd Pkt Len Std'].item(),
            bwd_pkt_len_max = df['Bwd Pkt Len Max'].item(),
            bwd_pkt_len_min = df['Bwd Pkt Len Min'].item(),
            bwd_pkt_len_mean = df['Bwd Pkt Len Mean'].item(),
            bwd_pkt_len_std = df['Bwd Pkt Len Std'].item(),
            flow_byts_s = df['Flow Byts/s'].item(),
            flow_pkts_s = df['Flow Pkts/s'].item(),
            flow_iat_mean = df['Flow IAT Mean'].item(),
            flow_iat_std = df['Flow IAT Std'].item(),
            flow_iat_max = df['Flow IAT Max'].item(),
            flow_iat_min = df['Flow IAT Min'].item(),
            fwd_iat_tot = df['Fwd IAT Tot'].item(),
            fwd_iat_mean = df['Fwd IAT Mean'].item(),
            fwd_iat_std = df['Fwd IAT Std'].item(),
            fwd_iat_max = df['Fwd IAT Max'].item(),
            fwd_iat_min = df['Fwd IAT Min'].item(),
            bwd_iat_tot = df['Bwd IAT Tot'].item(),
            bwd_iat_mean = df['Bwd IAT Mean'].item(),
            bwd_iat_std = df['Bwd IAT Std'].item(),
            bwd_iat_max = df['Bwd IAT Max'].item(),
            bwd_iat_min = df['Bwd IAT Min'].item(),
            fwd_psh_flags = df['Fwd PSH Flags'].item(),
            bwd_psh_flags = df['Bwd PSH Flags'].item(),
            fwd_urg_flags = df['Fwd URG Flags'].item(),
            bwd_urg_flags = df['Bwd URG Flags'].item(),
            fwd_header_len = df['Fwd Header Len'].item(),
            bwd_header_len = df['Bwd Header Len'].item(),
            fwd_pkts_s = df['Fwd Pkts/s'].item(),
            bwd_pkts_s = df['Bwd Pkts/s'].item(),
            pkt_len_min = df['Pkt Len Min'].item(),
            pkt_len_max = df['Pkt Len Max'].item(),
            pkt_len_mean = df['Pkt Len Mean'].item(),
            pkt_len_std = df['Pkt Len Std'].item(),
            pkt_len_var = df['Pkt Len Var'].item(),
            fin_flag_cnt = df['FIN Flag Cnt'].item(),
            syn_flag_cnt = df['SYN Flag Cnt'].item(),
            rst_flag_cnt = df['RST Flag Cnt'].item(),
            psh_flag_cnt = df['PSH Flag Cnt'].item(),
            ack_flag_cnt = df['ACK Flag Cnt'].item(),
            urg_flag_cnt = df['URG Flag Cnt'].item(),
            cwe_flag_cnt = df['CWE Flag Count'].item(),
            ece_flag_cnt = df['ECE Flag Cnt'].item(),
            down_up_ratio = df['Down/Up Ratio'].item(),
            pkt_size_avg = df['Pkt Size Avg'].item(),
            fwd_seg_size_avg = df['Fwd Seg Size Avg'].item(),
            bwd_seg_size_avg = df['Bwd Seg Size Avg'].item(),
            fwd_byts_b_avg = df['Fwd Byts/b Avg'].item(),
            fwd_pkts_b_avg = df['Fwd Pkts/b Avg'].item(),
            fwd_blk_rate_avg = df['Fwd Blk Rate Avg'].item(),
            bwd_byts_b_avg = df['Bwd Byts/b Avg'].item(),
            bwd_pkts_b_avg = df['Bwd Pkts/b Avg'].item(),
            bwd_blk_rate_avg = df['Bwd Blk Rate Avg'].item(),
            subflow_fwd_pkts = df['Subflow Fwd Pkts'].item(),
            subflow_fwd_byts = df['Subflow Fwd Byts'].item(),
            subflow_bwd_pkts = df['Subflow Bwd Pkts'].item(),
            subflow_bwd_byts = df['Subflow Bwd Byts'].item(),
            init_fwd_win_byts = df['Init Fwd Win Byts'].item(),
            init_bwd_win_byts = df['Init Bwd Win Byts'].item(),
            fwd_act_data_pkts = df['Fwd Act Data Pkts'].item(),
            fwd_seg_size_min = df['Fwd Seg Size Min'].item(),
            active_mean = df['Active Mean'].item(),
            active_std = df['Active Std'].item(),
            active_max = df['Active Max'].item(),
            active_min = df['Active Min'].item(),
            idle_mean = df['Idle Mean'].item(),
            idle_std = df['Idle Std'].item(),
            idle_max = df['Idle Max'].item(),
            idle_min = df['Idle Min'].item(),
        )
    except:
        abort(400, 'Invalid Data')