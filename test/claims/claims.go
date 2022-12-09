package claims

type PrivateClaims struct {
	Kubernetes Kubernetes `json:"kubernetes.io,omitempty"`
}

type Kubernetes struct {
	Namespace string `json:"namespace,omitempty"`
	Svcacct   Ref    `json:"serviceaccount,omitempty"`
	Pod       *Ref   `json:"pod,omitempty"`
	Secret    *Ref   `json:"secret,omitempty"`
}

type Ref struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}
