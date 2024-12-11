from gear import Working_gears
import streamlit as st
import pickle as pkl
from pathlib import Path

url = st.text_input('Type URL')

rf_pipe = pkl.load(open('model/rf_pipe.pkl' , 'rb'))
light_pipe = pkl.load(open('model/light_pipe.pkl' , 'rb'))
xgb_pipe = pkl.load(open('model/xgb_pipe.pkl','rb'))

gear = Working_gears(url)

url = gear.main()

if st.button('Random Forest'):
    st.markdown("### Prediction With Random Forest")
    pred = rf_pipe.predict(url)
    if int(pred[0]) == 0:
        res = "SAFE"

    elif int(pred[0]) == 1.0:
        res = "DEFACEMENT"

    elif int(pred[0]) == 2.0:
        res = "PHISHING"

    elif int(pred[0]) == 3.0:
        res = "MALWARE"

    st.markdown('## ' + res)

if st.button('Light GBM'):
    st.markdown("### Prediction With Light GBM")
    pred = light_pipe.predict(url)
    if int(pred[0]) == 0:
        res = "SAFE"

    elif int(pred[0]) == 1.0:
        res = "DEFACEMENT"

    elif int(pred[0]) == 2.0:
        res = "PHISHING"

    elif int(pred[0]) == 3.0:
        res = "MALWARE"

    st.markdown('## ' + res)

if st.button('XGBoost'):
    st.markdown("### Prediction With XGBoost")
    pred = xgb_pipe.predict(url)
    if int(pred[0]) == 0:
        res = "SAFE"

    elif int(pred[0]) == 1.0:
        res = "DEFACEMENT"

    elif int(pred[0]) == 2.0:
        res = "PHISHING"

    elif int(pred[0]) == 3.0:
        res = "MALWARE"

    st.markdown('## '+ res)

# streamlit run app.py