"""Model preprocessing factories; all learned transformations fit inside training pipelines."""
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from .feature_schema import FEATURES

NUMERIC=[f for f in FEATURES if f!="TLD"]
def make_preprocessor():
    return ColumnTransformer([("numeric",Pipeline([("imputer",SimpleImputer(strategy="median")),("scaler",StandardScaler())]),NUMERIC),
                              ("tld",OneHotEncoder(handle_unknown="ignore",min_frequency=2),["TLD"])],remainder="drop")
def make_pipeline(model):
    return Pipeline([("preprocess",make_preprocessor()),("model",model)])
