using Microsoft.Extensions.PlatformAbstractions;
using Newtonsoft.Json;
using System.IO;

namespace Utilities
{
    public static class JsonExtender
    {
        /// <summary>
        /// allows completion of relative pathes
        /// if no basePath specified then the {ApplicationBasePath} will be used for completion
        /// already rooted pathes and null pathes remains unchanged
        /// </summary>
        /// <param name="path"></param>
        /// <param name="basePath"></param>
        /// <returns></returns>
        public static string EnsureFullPath (this string path, string basePath = null)
        {
            if (string.IsNullOrEmpty(path) || Path.IsPathRooted(path))
                return path;
            return Path.Combine(basePath ?? PlatformServices.Default.Application.ApplicationBasePath, path);
        }

        /// <summary>
        /// use it like:
        /// as object: YourPocoClass yourPoco = new YourPocoClass().JsonReadFrom("FullFilename");
        /// as list: List<YourPocoClass> yourPoco = new List<YourPocoClass>().JsonReadFrom("FullFilename");
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        public static T JsonReadFrom<T>(this T data, string path)
        {
            string json = File.ReadAllText(path);
            return JsonConvert.DeserializeObject<T>(json);
        }

        /// <summary>
        /// use it like:
        /// yourPoco.JsonWriteTo("FullFilename");
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="path"></param>
        public static void JsonWriteTo<T>(this T data, string path)
        {
            string json = JsonConvert.SerializeObject(data, Formatting.Indented);
            File.WriteAllText(path, json);
        }
    }
}
