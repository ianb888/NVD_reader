using System;
using System.Runtime.Serialization;
using SerializerLib;

namespace NVD_reader
{
    [Serializable()]
    public class CVE_entry : ISerializable
    {
        private string _name;
        private entryType _entry;

        public string name { get { return _name; } set { _name = value; } }
        public entryType entry { get { return _entry; } set { _entry = value; } }

        public CVE_entry(entryType l_entry)
        {
            try
            {
                _entry = l_entry;
                _name = l_entry.name;
            }
            catch (Exception eX)
            {
                Console.Error.WriteLine("Exception in " + this.GetType().Name + " : " + eX);
            }
        }

        public override bool Equals(Object obj1)
        {
            // Check for null values and compare run-time types.
            if (obj1 == null || GetType() != obj1.GetType())
            {
                return false;
            }

            CVE_entry obj2 = obj1 as CVE_entry;
            if (obj2 == null)
            {
                return false;
            }

            return this.name.Equals(obj2.name);
        }

        public static bool operator ==(CVE_entry a, CVE_entry b)
        {
            // If both are null, or both are same instance, return true.
            if (Object.ReferenceEquals(a, b))
            {
                return true;
            }

            // If one is null, but not both, return false.
            if (((object)a == null) || ((object)b == null))
            {
                return false;
            }

            // Return true if the fields match:
            return a.name == b.name;
        }

        public static bool operator !=(CVE_entry a, CVE_entry b)
        {
            return !(a == b);
        }

        public override int GetHashCode()
        {
            string[] sections = _name.Split('-');
            string alertID = sections[1] + sections[2];
            return Convert.ToInt32(alertID);
        }

        void ISerializable.GetObjectData(SerializationInfo oInfo, StreamingContext oContext)
        {
            oInfo.AddValue("NVD_name", this._name);
            oInfo.AddValue("NVD_entry", this._entry);
        }

        public CVE_entry(SerializationInfo oInfo, StreamingContext ctxt)
        {
            this._name = (string)oInfo.GetValue("NVD_name", typeof(string));
            this._entry = (entryType)oInfo.GetValue("NVD_entry", typeof(entryType));
        }
    }
}