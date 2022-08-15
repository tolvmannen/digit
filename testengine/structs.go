package main

/*
type User struct {
                Name   string `mapstructure:"name"`
                Pubkey string `mapstructure:"pubkey"`
        }

*/

type LabGroup struct {
	GroupName string              `mapstructure:"groupname"`
	Domain    string              `mapstructure:"domain"`
	IpV4      string              `mapstructure:"ipv4"`
	User      []map[string]string `mapstructure:"user"`
}

type LabGroups struct {
	Group []LabGroup `mapstructure:"groups"`
}
