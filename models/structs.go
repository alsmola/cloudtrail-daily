package models

type RegionUsages map[string]RegionUsage

type RegionUsage struct {
	Region string `json:"region"`
	Usages Usages `json:"usages"`
}

type Usages map[string]Usage

type Usage struct {
	Subject  Subject            `json:"subject"`
	Services map[string]Service `json:"services"`
}

type Service struct {
	Actions map[string]Action `json:""actions"`
}

type Action struct {
	Resources []string `json:"resources"`
}

type Subject struct {
	User *User `json:"user,omitempty"`
	Role *Role `json:"role,omitempty"`
}

type User struct {
	Account string `json:"account"`
	Name    string `json:"name"`
}

type Role struct {
	Account string `json:"account"`
	Name    string `json:"name"`
	User    *User  `json:"user"`
}

func (r *RegionUsages) String() string {
	output := "\n"
	for _, ru := range *r {
		output = output + "Region: " + ru.Region + "\n"
		for _, u := range ru.Usages {
			if u.Subject.User != nil {
				output = output + "\tUser: " + u.Subject.User.Name + "\n"
			} else {
				output = output + "\tRole: " + u.Subject.Role.Name + "\n"
			}
			for sName, service := range u.Services {
				output = output + "\t\tService: " + sName + "\n"
				for aName, _ := range service.Actions {
					output = output + "\t\t\tAction: " + aName + "\n"
				}
			}
		}
	}
	return output
}
